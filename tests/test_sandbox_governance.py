"""Signed permit -> StrictKernel -> registered sandbox handler -> runsc boundary.

Real runtime portion is enabled only by dedicated Linux/gVisor acceptance CI.
A test-only issuer is separate from the public-only trusted executor.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import unittest

from shards_agent_os.sandbox_executor import ExecutionSpec, GVisorExecutor, SandboxResult

EXTRAS = all(importlib.util.find_spec(x) is not None for x in ("mcp", "cryptography", "shards_kernel"))
IMAGE = "busybox@sha256:" + "a" * 64


class RecordingExecutor(GVisorExecutor):
    def __init__(self):
        self.requests = []

    def run(self, spec):
        self.requests.append(spec)
        return SandboxResult(
            status="EXITED", exit_code=0, stdout="accepted\n", stderr="",
            duration_ms=2, fingerprint=spec.fingerprint(), cleanup_confirmed=True,
        )


def exact_args(image=IMAGE):
    return {
        "image": image,
        "argv": ["/bin/echo", "accepted"],
        "timeout_seconds": 20,
        "memory_megabytes": 256,
        "cpu_millicores": 500,
        "pids_limit": 32,
    }


def setup(issuer_key, runner):
    from shards_kernel import KernelConfig, StrictKernel, VirtualClock
    from shards_kernel.jurisdiction.policy import JurisdictionPolicy
    from shards_kernel.permits import PublicVerificationKey
    from shards_agent_os.governed_sandbox import create_governed_sandbox_server

    kernel = StrictKernel()
    kernel.boot(KernelConfig(kernel_id="sandbox-governance-test", variant="strict", clock=VirtualClock(1000)))
    kernel.set_policy(JurisdictionPolicy(
        allowed_actors=frozenset({"agent-alpha"}),
        allowed_tools=frozenset({"sandbox.exec"}),
    ))
    kernel.set_public_verifiers({
        "approval-key": PublicVerificationKey(
            issuer="external-approver", audience="sandbox-governance-test",
            public_key=issuer_key.public_key().public_bytes_raw(),
        ),
    })
    server = create_governed_sandbox_server(
        kernel, actor="agent-alpha", executor=runner
    )
    return kernel, server


def signed_permit(key, args, *, subject="agent-alpha", action="sandbox.exec"):
    from shards_kernel.issuer import sign_v2_permit
    from shards_kernel.integrations.wire import permit_to_mapping
    from shards_kernel.permits import PermitBuilder

    unsigned = (
        PermitBuilder()
        .issuer("external-approver").subject(subject)
        .jurisdiction("default").action(action).params(args)
        .max_executions(1)
        .valid_from_ms(0).valid_until_ms(2000)
        .proposal_hash("approved-by-independent-operator")
        .build_unsigned_v2(key_id="approval-key", audience="sandbox-governance-test")
    )
    return permit_to_mapping(sign_v2_permit(unsigned, key))


@unittest.skipUnless(EXTRAS, "Shards-Kernel crypto and MCP extras required")
class GovernedSandboxTests(unittest.TestCase):
    def test_public_key_only_required(self):
        from shards_kernel import KernelConfig, StrictKernel, VirtualClock
        from shards_kernel.jurisdiction.policy import JurisdictionPolicy
        from shards_agent_os.governed_sandbox import create_governed_sandbox_server

        kernel = StrictKernel()
        kernel.boot(KernelConfig(kernel_id="test", variant="strict", clock=VirtualClock(1000)))
        kernel.set_policy(JurisdictionPolicy(
            allowed_actors=frozenset({"agent-alpha"}),
            allowed_tools=frozenset({"sandbox.exec"}),
        ))
        with self.assertRaisesRegex(ValueError, "public-only"):
            create_governed_sandbox_server(
                kernel, actor="agent-alpha", executor=RecordingExecutor(),
            )

    def test_unsigned_invalid_or_replayed_never_reaches_executor(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from mcp import Client

        key = Ed25519PrivateKey.generate()
        runner = RecordingExecutor()
        kernel, server = setup(key, runner)
        args = exact_args()
        permit = signed_permit(key, args)

        async def exercise():
            async with Client(server, raise_exceptions=True) as client:
                tools = await client.list_tools()
                self.assertIn("governed_execute", {tool.name for tool in tools.tools})

                absent = await client.call_tool("governed_execute", {
                    "name": "sandbox.exec", "arguments": args,
                })
                self.assertTrue(absent.is_error)
                self.assertEqual(runner.requests, [])

                modified = await client.call_tool("governed_execute", {
                    "name": "sandbox.exec",
                    "arguments": {**args, "cpu_millicores": 1500},
                    "permit": permit,
                })
                self.assertTrue(modified.is_error)
                self.assertEqual(runner.requests, [])

                wrong_actor = await client.call_tool("governed_execute", {
                    "name": "sandbox.exec", "arguments": args,
                    "permit": signed_permit(key, args, subject="agent-beta"),
                })
                self.assertTrue(wrong_actor.is_error)
                self.assertEqual(runner.requests, [])

                missing = await client.call_tool("governed_execute", {
                    "name": "sandbox.exec",
                    "arguments": {key: value for key, value in args.items()
                                  if key != "pids_limit"},
                    "permit": permit,
                })
                self.assertTrue(missing.is_error)
                self.assertEqual(runner.requests, [])

                accepted = await client.call_tool("governed_execute", {
                    "name": "sandbox.exec", "arguments": args, "permit": permit,
                })
                self.assertFalse(accepted.is_error, accepted)
                body = json.loads(accepted.content[0].text)
                self.assertEqual(body["result"]["status"], "EXITED")
                self.assertEqual(body["result"]["stdout"], "accepted\n")
                self.assertEqual(len(runner.requests), 1)
                self.assertIsInstance(runner.requests[0], ExecutionSpec)

                replay = await client.call_tool("governed_execute", {
                    "name": "sandbox.exec", "arguments": args, "permit": permit,
                })
                self.assertTrue(replay.is_error)
                self.assertEqual(len(runner.requests), 1)
        asyncio.run(exercise())
        self.assertGreater(len(kernel.export_evidence().ledger_entries), 0)


@unittest.skipUnless(
    EXTRAS and sys.platform.startswith("linux") and os.getenv("SHARDS_SANDBOX_LIVE") == "1",
    "Requires real runsc integration runner and optional MCP extras",
)
class GovernedSandboxRealGVisorTests(unittest.TestCase):
    def test_real_signed_permit_launches_one_gvisor_workload(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from mcp import Client

        image = os.environ.get("SHARDS_SANDBOX_IMAGE")
        if not image:
            self.fail("Missing pinned SHARDS_SANDBOX_IMAGE")
        key = Ed25519PrivateKey.generate()
        kernel, server = setup(key, GVisorExecutor())
        args = exact_args(image=image)
        permit = signed_permit(key, args)

        async def exercise():
            async with Client(server, raise_exceptions=True) as client:
                command = {"name": "sandbox.exec", "arguments": args, "permit": permit}
                accepted = await client.call_tool("governed_execute", command)
                self.assertFalse(accepted.is_error, accepted)
                result = json.loads(accepted.content[0].text)["result"]
                self.assertEqual(result["status"], "EXITED", result)
                self.assertEqual(result["stdout"].strip(), "accepted")
                self.assertTrue(result["cleanup_confirmed"])
                replay = await client.call_tool("governed_execute", command)
                self.assertTrue(replay.is_error)
        asyncio.run(exercise())
        self.assertGreater(len(kernel.export_evidence().ledger_entries), 0)


if __name__ == "__main__":
    unittest.main()
