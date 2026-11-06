"""Persistent signed sandbox operator: verified replay across restart.

Live class additionally runs a *separate* stdio MCP operator OS process
against real gVisor. Real execution is mandatory only in Linux runsc CI.
"""
from __future__ import annotations

import asyncio
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

from shards_agent_os.sandbox_operator import (
    _secure_database, build_persistent_sandbox_kernel,
)

from test_sandbox_governance import RecordingExecutor, exact_args

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from mcp import Client, StdioServerParameters
    from shards_kernel.integrations.wire import permit_to_mapping
    from shards_kernel.issuer import sign_v2_permit
    from shards_kernel.permits import PermitBuilder
    DEPENDENCIES = True
except ImportError:
    DEPENDENCIES = False

KERNEL_ID = "sandbox-durable-e2e"
ACTOR = "agent-alpha"
ISSUER = "independent-issuer"
KEY_ID = "independent-key"


def scoped_permit(private_key, args):
    now = int(time.time() * 1000)
    token = (
        PermitBuilder()
        .issuer(ISSUER).subject(ACTOR).jurisdiction("default")
        .action("sandbox.exec").params(args)
        .max_executions(1)
        .valid_from_ms(now - 30000).valid_until_ms(now + 120000)
        .proposal_hash("external-approval")
        .build_unsigned_v2(key_id=KEY_ID, audience=KERNEL_ID)
    )
    return permit_to_mapping(sign_v2_permit(token, private_key))


@unittest.skipUnless(sys.platform == "linux", "Linux POSIX filesystem required")
class PrivateAuditTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "audit.sqlite3"

    def test_create_private_regular_file(self):
        path = _secure_database(str(self.path))
        self.assertEqual(path, self.path)
        self.assertTrue(path.is_file())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(_secure_database(str(self.path)), path)

    def test_reject_world_accessible_parent(self):
        os.chmod(self.root, 0o755)
        with self.assertRaises(PermissionError):
            _secure_database(str(self.path))

    def test_reject_world_accessible_audit_file(self):
        self.path.touch(mode=0o600)
        os.chmod(self.path, 0o644)
        with self.assertRaises(PermissionError):
            _secure_database(str(self.path))

    def test_refuse_symlink_and_relative_path(self):
        with self.assertRaises(ValueError):
            _secure_database("relative.sqlite3")
        target = self.root / "target.sqlite3"
        target.touch(mode=0o600)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            _secure_database(str(self.path))


@unittest.skipUnless(sys.platform == "linux" and DEPENDENCIES, "Linux and kernel crypto/MCP extras required")
class DurableReplayTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = str(self.root / "audit.sqlite3")
        self.key = Ed25519PrivateKey.generate()

    def fresh_kernel(self):
        return build_persistent_sandbox_kernel(
            kernel_id=KERNEL_ID, actor=ACTOR, audit_db=self.path,
            issuer=ISSUER, key_id=KEY_ID,
            public_key_hex=self.key.public_key().public_bytes_raw().hex(),
        )

    def test_signer_cannot_be_replaced_by_invalid_input(self):
        with self.assertRaises(ValueError):
            build_persistent_sandbox_kernel(
                kernel_id=KERNEL_ID, actor=ACTOR, audit_db=self.path,
                issuer=ISSUER, key_id=KEY_ID, public_key_hex="not-a-key",
            )

    def test_signed_permit_rejected_after_operator_restarts(self):
        from shards_agent_os.governed_sandbox import create_governed_sandbox_server

        args = exact_args()
        permit = scoped_permit(self.key, args)
        first_runner = RecordingExecutor()
        first_kernel = self.fresh_kernel()
        first_server = create_governed_sandbox_server(
            first_kernel, actor=ACTOR, executor=first_runner
        )

        async def execute(server, permit_data):
            async with Client(server, raise_exceptions=True) as client:
                return await client.call_tool("governed_execute", {
                    "name": "sandbox.exec", "arguments": args, "permit": permit_data,
                })

        accepted = asyncio.run(execute(first_server, permit))
        self.assertFalse(accepted.is_error, accepted)
        self.assertEqual(len(first_runner.requests), 1)
        self.assertGreater(len(first_kernel.export_evidence().ledger_entries), 0)

        second_runner = RecordingExecutor()
        second_kernel = self.fresh_kernel()
        second_server = create_governed_sandbox_server(
            second_kernel, actor=ACTOR, executor=second_runner
        )
        denied = asyncio.run(execute(second_server, permit))
        self.assertTrue(denied.is_error)
        self.assertEqual(second_runner.requests, [])
        self.assertGreater(
            len(second_kernel.export_evidence().ledger_entries),
            len(first_kernel.export_evidence().ledger_entries),
        )


@unittest.skipUnless(
    sys.platform == "linux" and DEPENDENCIES and os.getenv("SHARDS_SANDBOX_LIVE") == "1",
    "Requires ephemeral real runsc Linux host and kernel crypto/MCP extras",
)
class DurableOperatorRealGVisorTests(unittest.TestCase):
    def test_real_stdio_operator_executes_once_and_rejects_replay_after_restart(self):
        image = os.environ.get("SHARDS_SANDBOX_IMAGE", "")
        self.assertTrue(image, "Missing preloaded pinned image")
        with tempfile.TemporaryDirectory() as root:
            audit = str(Path(root) / "sandbox-operator-audit.sqlite3")
            key = Ed25519PrivateKey.generate()
            args = exact_args(image=image)
            permit = scoped_permit(key, args)
            cmd = [
                "-m", "shards_agent_os.sandbox_operator",
                "--kernel-id", KERNEL_ID, "--actor", ACTOR,
                "--audit-db", audit, "--issuer", ISSUER,
                "--key-id", KEY_ID,
                "--public-key-hex", key.public_key().public_bytes_raw().hex(),
            ]

            async def invoke():
                params = StdioServerParameters(
                    command=sys.executable, args=cmd,
                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                )
                async with Client(params, raise_exceptions=True) as client:
                    tools = await client.list_tools()
                    self.assertIn("governed_execute", {t.name for t in tools.tools})
                    return await client.call_tool("governed_execute", {
                        "name": "sandbox.exec", "arguments": args, "permit": permit,
                    })

            result = asyncio.run(invoke())
            self.assertFalse(result.is_error, result)
            replay = asyncio.run(invoke())
            self.assertTrue(replay.is_error)
            self.assertTrue(Path(audit).exists())
            self.assertEqual(stat.S_IMODE(Path(audit).stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
