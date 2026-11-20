"""Regression tests for Cloudflare Workers AI Qwen Chat Completions responses.

No live Workers AI calls, tokens, models, or host services required.
"""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from shards_agent_os.qwen_provider import ProviderError, WorkersAIProvider


class _FakeResponse:
    status = 200

    def __init__(self, payload):
        self.raw = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, _max_bytes):
        return self.raw


class _FakeOpener:
    def __init__(self, response):
        self.response = response
        self.request = None

    def open(self, request, timeout):
        self.request = request
        return self.response


class WorkersAIResponseContractTests(unittest.TestCase):
    def setUp(self):
        self.provider = WorkersAIProvider(account_id="a" * 32, max_tokens=400)

    def complete(self, result):
        opener = _FakeOpener(_FakeResponse({"success": True, "result": result}))
        with patch.dict(os.environ, {"CF_WORKERS_AI_TOKEN": "t" * 48}), patch(
            "shards_agent_os.qwen_provider.urllib.request.build_opener",
            return_value=opener,
        ):
            reply = self.provider.complete(system="system", user="user", timeout_s=20)
        return reply, json.loads(opener.request.data)

    def test_qwen_chat_completions_envelope(self):
        result = {
            "id": "completion-test",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "QWEN_INFERENCE_OK", "reasoning": "internal"},
                "finish_reason": "stop",
            }],
        }
        reply, payload = self.complete(result)
        self.assertEqual(reply.text, "QWEN_INFERENCE_OK")
        self.assertEqual(reply.model, "@cf/qwen/qwen3.8-27b")
        self.assertEqual(payload["max_completion_tokens"], 400)
        self.assertEqual(payload["reasoning_effort"], "low")
        self.assertIs(payload["stream"], False)
        self.assertNotIn("max_tokens", payload)

    def test_legacy_response_uses_legacy_token_budget(self):
        self.provider = WorkersAIProvider(
            account_id="a" * 32, model="@cf/qwen/qwen2.5-coder-32b-instruct",
            max_tokens=75,
        )
        reply, payload = self.complete({"response": "legacy reply"})
        self.assertEqual(reply.text, "legacy reply")
        self.assertEqual(payload["max_tokens"], 75)
        self.assertIs(payload["stream"], False)
        self.assertNotIn("max_completion_tokens", payload)
        self.assertNotIn("reasoning_effort", payload)

    def test_legacy_truncated_response_is_rejected_when_signalled(self):
        self.provider = WorkersAIProvider(
            account_id="a" * 32, model="@cf/qwen/qwen2.5-coder-32b-instruct",
            max_tokens=75,
        )
        with self.assertRaisesRegex(ProviderError, "PROVIDER_INCOMPLETE_REPLY"):
            self.complete({"response": "partial", "finish_reason": "length"})

    def test_reasoning_only_reply_has_no_user_text(self):
        result = {"choices": [{
            "message": {"role": "assistant", "content": None, "reasoning": "thinking"},
            "finish_reason": "stop",
        }]}
        with self.assertRaisesRegex(ProviderError, "PROVIDER_INVALID_JSON"):
            self.complete(result)

    def test_truncated_reply_is_rejected(self):
        result = {"choices": [{
            "message": {"role": "assistant", "content": "incomplete"},
            "finish_reason": "length",
        }]}
        with self.assertRaisesRegex(ProviderError, "PROVIDER_INCOMPLETE_REPLY"):
            self.complete(result)

    def test_malformed_choices_are_rejected(self):
        for result in (
            {"choices": []},
            {"choices": "not a list"},
            {"choices": [None]},
            {"choices": [{"message": {"role": "user", "content": "not assistant"}}]},
            {"choices": [{"message": {"role": "assistant", "content": ""}}]},
            {"choices": [{"message": {"role": "assistant", "content": "ok",
                                      "tool_calls": [{"id": "unexpected"}]}}]},
        ):
            with self.subTest(result=result), self.assertRaises(ProviderError):
                self.complete(result)


if __name__ == "__main__":
    unittest.main()
