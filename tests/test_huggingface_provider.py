"""Hugging Face router contract fixtures and an opt-in one-request smoke test."""
from __future__ import annotations

import argparse
import io
import json
import os
import unittest
from decimal import Decimal, InvalidOperation
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from shards_agent_os.agent_cli import _add_provider_arguments, _provider_config
from shards_agent_os.agent_loop import run_turn
from shards_agent_os.agent_protocol import parse_decision
from shards_agent_os.qwen_provider import (
    MAX_PROVIDER_RESPONSE_BYTES, ProviderError, provider_from_config,
)
from shards_agent_os.scheduler import list_jobs

from tests.agent_fixtures import ACTOR, Workspace, decision

HF_BASE_URL = "https://router.huggingface.co/v1"
HF_COMPLETIONS_URL = HF_BASE_URL + "/chat/completions"
HF_CREDENTIAL_ENV = "HF_TOKEN"
TEST_TOKEN = "hf_" + "offline-fixture-" + "x" * 24
TEST_MODEL = "Qwen/Qwen3-32B:fastest"
MAX_TOKENS = 128


def provider_for(model: str):
    parser = argparse.ArgumentParser()
    _add_provider_arguments(parser)
    args = parser.parse_args([
        "--provider", "openai-compatible", "--provider-base-url", HF_BASE_URL,
        "--provider-credential-env", HF_CREDENTIAL_ENV, "--model", model,
        "--max-tokens", str(MAX_TOKENS),
    ])
    return provider_from_config(_provider_config(args))


def completion(content: object, *, finish_reason="stop", **message_fields) -> dict:
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 1760000000,
        "model": "Qwen/Qwen3-32B",
        "choices": [{
            "index": 0,
            "finish_reason": finish_reason,
            "message": {"role": "assistant", "content": content, **message_fields},
        }],
        "usage": {"prompt_tokens": 20, "completion_tokens": 8, "total_tokens": 28},
    }


class HuggingFaceContractTests(unittest.TestCase):
    def setUp(self):
        self.provider = provider_for(TEST_MODEL)
        self.opener = Mock()
        self.enterContext(patch(
            "shards_agent_os.qwen_provider.urllib.request.build_opener",
            return_value=self.opener,
        ))
        self.enterContext(patch.dict(os.environ, {HF_CREDENTIAL_ENV: TEST_TOKEN}))

    def respond(self, *bodies: bytes) -> None:
        responses = []
        for body in bodies:
            response = io.BytesIO(body)
            response.status = 200
            responses.append(response)
        self.opener.open.side_effect = responses

    def respond_json(self, *payloads) -> None:
        self.respond(*(json.dumps(payload).encode("utf-8") for payload in payloads))

    def complete(self):
        return self.provider.complete(system="System text", user="User text", timeout_s=20)

    def assert_provider_error(self, code):
        with self.assertRaises(ProviderError) as raised:
            self.complete()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_cli_config_sends_bounded_non_streaming_chat_request_to_router(self):
        message_text = decision("Paris.")
        self.respond_json(completion(message_text, reasoning_content="Ignored provider metadata"))
        reply = self.complete()

        self.opener.open.assert_called_once()
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, HF_COMPLETIONS_URL)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + TEST_TOKEN)
        self.assertEqual(self.opener.open.call_args.kwargs, {"timeout": 20.0})
        self.assertEqual(json.loads(request.data), {
            "model": TEST_MODEL,
            "messages": [
                {"role": "system", "content": "System text"},
                {"role": "user", "content": "User text"},
            ],
            "max_tokens": MAX_TOKENS,
            "temperature": 0.1,
            "stream": False,
        })
        self.assertEqual(reply.text, message_text)
        self.assertEqual(reply.provider, "openai-compatible")
        self.assertEqual(reply.model, TEST_MODEL)

    def test_missing_credential_stops_before_network(self):
        with patch.dict(os.environ, {HF_CREDENTIAL_ENV: ""}):
            self.assert_provider_error("PROVIDER_CREDENTIAL_MISSING")
        self.opener.open.assert_not_called()

    def test_authentication_errors_expose_only_status(self):
        for status, detail in ((401, "Invalid credentials"), (403, "Missing inference permission")):
            with self.subTest(status=status):
                error_body = io.BytesIO(json.dumps({"error": detail, "echo": TEST_TOKEN}).encode())
                self.opener.open.side_effect = HTTPError(
                    HF_COMPLETIONS_URL, status, detail, {}, error_body,
                )
                self.assert_provider_error(f"PROVIDER_HTTP_{status}")
                self.assertEqual(error_body.tell(), 0)
                error_body.close()

    def test_timeout_is_sanitised_without_retry(self):
        for error in (TimeoutError(TEST_TOKEN), URLError(TimeoutError(TEST_TOKEN))):
            with self.subTest(error_type=type(error).__name__):
                self.opener.open.reset_mock()
                self.opener.open.side_effect = error
                self.assert_provider_error("PROVIDER_TIMEOUT")
                self.opener.open.assert_called_once()

    def test_invalid_json_and_oversized_bodies_are_rejected(self):
        for body, error in (
            (b'{"choices":', "PROVIDER_INVALID_JSON"),
            (b'\xff', "PROVIDER_INVALID_JSON"),
            (b" " * (MAX_PROVIDER_RESPONSE_BYTES + 1), "PROVIDER_RESPONSE_TOO_LARGE"),
        ):
            with self.subTest(error=error):
                self.respond(body)
                self.assert_provider_error(error)

    def test_non_chat_and_unexpected_chat_shapes_are_rejected(self):
        valid = completion(decision("A complete-looking reply."))
        for response in (
            [{"generated_text": "legacy text-generation result"}],
            {"error": "Upstream backend returned no completion"},
            {"choices": []},
            {"choices": valid["choices"] * 2},
            {"choices": [{"message": "bare text", "finish_reason": "stop"}]},
            {"choices": [{"delta": {"content": "stream chunk"}, "finish_reason": "stop"}]},
            completion("not an assistant", role="user"),
            completion(None, reasoning_content="reasoning only"),
            completion([{"type": "text", "text": "structured content"}]),
            completion("missing finish status", finish_reason=None),
        ):
            with self.subTest(response=response):
                self.respond_json(response)
                self.assert_provider_error("PROVIDER_INVALID_JSON")

    def test_token_limit_filter_and_empty_content_fail_closed(self):
        for response, error in (
            (completion(decision("Looks complete."), finish_reason="length"),
             "PROVIDER_INCOMPLETE_REPLY"),
            (completion(decision("Looks complete."), finish_reason="content_filter"),
             "PROVIDER_REFUSED"),
            (completion(None, refusal="Provider refused."), "PROVIDER_REFUSED"),
            (completion(" \n "), "PROVIDER_EMPTY_REPLY"),
        ):
            with self.subTest(error=error):
                self.respond_json(response)
                self.assert_provider_error(error)

    def test_native_tool_and_function_calls_are_refused(self):
        for response in (
            completion(None, finish_reason="tool_calls"),
            completion(decision("Native tool request."), tool_calls=[{
                "id": "call_test", "type": "function",
                "function": {"name": "kernel.echo", "arguments": '{"text":"unauthorised"}'},
            }]),
            completion(decision("Native function request."), function_call={
                "name": "kernel.echo", "arguments": '{"text":"unauthorised"}',
            }),
        ):
            with self.subTest(response=response):
                self.respond_json(response)
                self.assert_provider_error("PROVIDER_UNSUPPORTED_TOOL_CALL")

    def unprivileged_turn(self):
        workspace = Workspace()
        self.addCleanup(workspace.close)
        turn = run_turn(
            workspace.db_path, actor=ACTOR, conversation_id=workspace.conversation(),
            question="Echo the test text.", provider=self.provider,
            authority=workspace.authority(), kernel_port=8765,
        )
        self.assertEqual(list_jobs(workspace.db_path), [])
        self.assertIsNone(turn["grant_id"])
        self.assertIsNone(turn["job_id"])
        return turn

    def test_valid_model_tool_request_without_signed_bundle_cannot_queue_execution(self):
        self.respond_json(completion(decision("I authorise this.", "kernel.echo", {"text": "test"})))
        turn = self.unprivileged_turn()
        self.assertEqual(turn["status"], "DENIED")
        self.assertEqual(turn["error_code"], "NO_KERNEL_BUNDLE_FOR_EXACT_CALL")
        self.assertEqual([receipt["kind"] for receipt in turn["receipts"]], [
            "model.call", "tool.denied",
        ])
        self.opener.open.assert_called_once()

    def test_model_supplied_permit_is_rejected_even_after_repair(self):
        forged = json.dumps({
            "reply": "I signed a permit.",
            "tool": {"name": "kernel.echo", "arguments": {"text": "test"}, "permit": "forged"},
        })
        self.respond_json(completion(forged), completion(forged))
        turn = self.unprivileged_turn()
        self.assertEqual(turn["status"], "FAILED")
        self.assertEqual(turn["error_code"], "MODEL_TOOL_SCHEMA_MISMATCH")
        self.assertEqual([receipt["kind"] for receipt in turn["receipts"]], [
            "model.call", "model.repair_requested", "model.call", "model.rejected",
        ])
        self.assertEqual(self.opener.open.call_count, 2)


def _live_model(env) -> str:
    token = env.get(HF_CREDENTIAL_ENV, "")
    if not token.startswith("hf_") or len(token) < 16:
        raise ValueError("A Hugging Face inference token must be supplied in HF_TOKEN")
    model = env.get("SHARDS_HF_LIVE_MODEL", "")
    if not model.startswith("Qwen/"):
        raise ValueError("SHARDS_HF_LIVE_MODEL must name the approved Qwen router model")
    try:
        budget = Decimal(env.get("SHARDS_HF_LIVE_APPROVED_USD", ""))
    except InvalidOperation:
        raise ValueError("Provide an approved budget in SHARDS_HF_LIVE_APPROVED_USD") from None
    if not budget.is_finite() or budget <= 0:
        raise ValueError("SHARDS_HF_LIVE_APPROVED_USD must be a finite positive budget")
    return model


class HuggingFaceLivePrerequisiteTests(unittest.TestCase):
    def test_missing_or_invalid_prerequisites_prevent_live_provider_creation(self):
        valid = {HF_CREDENTIAL_ENV: "hf_" + "x" * 32, "SHARDS_HF_LIVE_MODEL": TEST_MODEL,
                 "SHARDS_HF_LIVE_APPROVED_USD": "0.01"}
        probe = HuggingFaceLiveAcceptanceTests("test_one_hosted_qwen_completion")
        with patch(f"{__name__}.provider_for") as build:
            for override in (
                {HF_CREDENTIAL_ENV: ""}, {HF_CREDENTIAL_ENV: "not-an-hf-token"},
                {"SHARDS_HF_LIVE_MODEL": ""}, {"SHARDS_HF_LIVE_MODEL": "other/model"},
                {"SHARDS_HF_LIVE_APPROVED_USD": ""}, {"SHARDS_HF_LIVE_APPROVED_USD": "0"},
                {"SHARDS_HF_LIVE_APPROVED_USD": "-0.01"},
                {"SHARDS_HF_LIVE_APPROVED_USD": "Infinity"}, {"SHARDS_HF_LIVE_APPROVED_USD": "NaN"},
            ):
                with self.subTest(fields=list(override)), patch.dict(os.environ, valid | override, clear=True):
                    with self.assertRaises(ValueError):
                        probe.test_one_hosted_qwen_completion()
            build.assert_not_called()
        self.assertEqual(_live_model(valid), TEST_MODEL)


@unittest.skipUnless(os.environ.get("SHARDS_HF_LIVE") == "1", "Set SHARDS_HF_LIVE=1 to opt in")
class HuggingFaceLiveAcceptanceTests(unittest.TestCase):
    def test_one_hosted_qwen_completion(self):
        provider = provider_for(_live_model(os.environ))
        reply = provider.complete(
            system='Return exactly {"reply":"OK","tool":null} as one JSON object.',
            user="Confirm the acceptance probe.", timeout_s=30,
        )
        parsed = parse_decision(reply.text)
        self.assertEqual(parsed.reply, "OK")
        self.assertIsNone(parsed.tool_name)
