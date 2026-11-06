"""Offline signing contract: exact digest approval and public-only verification."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from shards_kernel.integrations.wire import permit_from_mapping
from shards_kernel.issuer import DOMAIN
from shards_kernel.permits import canonical_permit_bytes

from shards_agent_os import offline_approver as approve

_IMAGE = "busybox@sha256:" + "a" * 64


def params():
    return {
        "image": _IMAGE,
        "argv": ["/bin/echo", "production-safe"],
        "timeout_seconds": 20,
        "memory_megabytes": 256,
        "cpu_millicores": 500,
        "pids_limit": 32,
    }


class OfflineApprovalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.hex"
        self.request = self.root / "arguments.json"
        self.permit = self.root / "permit.json"
        self.request.write_text(json.dumps(params()))
        os.chmod(self.request, 0o600)

    def keys(self):
        return approve.generate_key(
            private_path=str(self.private), public_path=str(self.public),
        )

    def issue(self, *, digest=None, ttl=120):
        return approve.issue_permit(
            private_key_path=str(self.private),
            request_path=str(self.request),
            output_path=str(self.permit),
            approval_digest=digest or approve._request(str(self.request))[1],
            issuer="independent-approver", key_id="approver-public",
            kernel_id="sandbox-pilot", actor="agent-alpha",
            ttl_seconds=ttl, now_ms=1_900_000_000_000,
        )

    def test_public_verifier_only_private_0600(self):
        meta = self.keys()
        self.assertRegex(meta["public_key_hex"], r"^[0-9a-f]{64}$")
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.public.stat().st_mode), 0o644)
        self.assertNotIn("PRIVATE KEY", self.public.read_text())
        self.assertNotIn("private", json.dumps(meta["public_key_hex"]))
        with self.assertRaises(FileExistsError):
            self.keys()

    def test_signed_v2_matches_exact_request_and_offline_public_key(self):
        self.keys()
        metadata = self.issue()
        self.assertTrue(metadata["output_created"])
        self.assertEqual(stat.S_IMODE(self.permit.stat().st_mode), 0o600)
        raw = json.loads(self.permit.read_text())
        token = permit_from_mapping(raw)
        self.assertEqual(token.version, 2)
        self.assertEqual(token.algorithm, "Ed25519")
        self.assertEqual(token.audience, "sandbox-pilot")
        self.assertEqual(token.action, "sandbox.exec")
        self.assertEqual(token.subject, "agent-alpha")
        self.assertEqual(token.params, params())
        self.assertEqual(token.max_executions, 1)
        self.assertEqual(token.proposal_hash, "sha256:" + metadata["approval_digest"])
        self.assertNotIn("PRIVATE KEY", self.permit.read_text())
        verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public.read_text().strip()))
        verifier.verify(bytes.fromhex(token.signature), DOMAIN + canonical_permit_bytes(token))

    def test_changed_argv_or_quota_blocks_signature(self):
        self.keys()
        _original, digest = approve._request(str(self.request))
        for altered in (
            {**params(), "argv": ["/bin/sh", "-c", "id"]},
            {**params(), "memory_megabytes": 512},
            {**params(), "image": "busybox@sha256:" + "b" * 64},
            {**params(), "timeout_seconds": 30},
        ):
            with self.subTest(altered=altered):
                self.request.write_text(json.dumps(altered))
                with self.assertRaises(PermissionError):
                    self.issue(digest=digest)
                self.assertFalse(self.permit.exists())

    def test_extra_or_missing_fields_rejected_before_signing(self):
        self.keys()
        for altered in (
            {**params(), "mount": "/etc"},
            {key: val for key, val in params().items() if key != "pids_limit"},
            {**params(), "argv": "echo wrong"},
            {**params(), "image": "busybox:latest"},
        ):
            with self.subTest(altered=altered):
                self.request.write_text(json.dumps(altered))
                with self.assertRaises(ValueError):
                    approve._request(str(self.request))
                self.assertFalse(self.permit.exists())

    def test_untrusted_key_permissions_and_symlinks_rejected(self):
        self.keys()
        os.chmod(self.private, 0o644)
        with self.assertRaises(PermissionError):
            self.issue()
        self.assertFalse(self.permit.exists())
        os.chmod(self.private, 0o600)
        path = self.root / "private-link.pem"
        path.symlink_to(self.private)
        with self.assertRaises(OSError):
            approve.issue_permit(
                private_key_path=str(path),
                request_path=str(self.request), output_path=str(self.permit),
                approval_digest=approve._request(str(self.request))[1],
                issuer="issuer", key_id="key", kernel_id="kernel", actor="actor",
                ttl_seconds=60,
            )

    def test_existing_output_cannot_be_overwritten(self):
        self.keys()
        self.permit.write_text("original\n")
        os.chmod(self.permit, 0o600)
        with self.assertRaises(FileExistsError):
            self.issue()
        self.assertEqual(self.permit.read_text(), "original\n")

    def test_short_and_long_time_windows_rejected(self):
        self.keys()
        for ttl in (0, 9, 301, True):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                self.issue(ttl=ttl)

    def test_offline_issued_permit_is_accepted_once_by_persistent_kernel(self):
        import asyncio
        from mcp import Client
        from shards_agent_os.sandbox_operator import build_persistent_sandbox_kernel
        from shards_agent_os.governed_sandbox import create_governed_sandbox_server
        from test_sandbox_governance import RecordingExecutor

        self.keys()
        request, digest = approve._request(str(self.request))
        metadata = approve.issue_permit(
            private_key_path=str(self.private),
            request_path=str(self.request),
            output_path=str(self.permit),
            approval_digest=digest,
            issuer="independent-approver",
            key_id="approver-public",
            kernel_id="sandbox-pilot",
            actor="agent-alpha",
            ttl_seconds=120,
        )
        wire = json.loads(self.permit.read_text())
        kernel = build_persistent_sandbox_kernel(
            kernel_id="sandbox-pilot",
            actor="agent-alpha",
            audit_db=str(self.root / "kernel.sqlite3"),
            issuer="independent-approver",
            key_id="approver-public",
            public_key_hex=self.public.read_text().strip(),
        )
        executor = RecordingExecutor()
        server = create_governed_sandbox_server(
            kernel, actor="agent-alpha", executor=executor,
        )

        async def call(permit_data, arguments):
            async with Client(server, raise_exceptions=True) as client:
                return await client.call_tool("governed_execute", {
                    "name": "sandbox.exec",
                    "arguments": arguments,
                    "permit": permit_data,
                })

        tampered = dict(request)
        tampered["cpu_millicores"] += 100
        denied = asyncio.run(call(wire, tampered))
        self.assertTrue(denied.is_error)
        self.assertEqual(executor.requests, [])

        accepted = asyncio.run(call(wire, request))
        self.assertFalse(accepted.is_error, accepted)
        self.assertEqual(len(executor.requests), 1)
        self.assertEqual(executor.requests[0].fingerprint(), metadata["approval_digest"])

        replay = asyncio.run(call(wire, request))
        self.assertTrue(replay.is_error)
        self.assertEqual(len(executor.requests), 1)

    def test_cli_emits_no_signing_key_bytes(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = approve.main([
                "keygen", "--private-key-file", str(self.private),
                "--public-key-file", str(self.public),
            ])
        self.assertEqual(status, 0)
        self.assertNotIn("PRIVATE KEY", stdout.getvalue())
        with contextlib.redirect_stdout(stdout):
            status = approve.main([
                "digest", "--arguments-file", str(self.request),
            ])
        self.assertEqual(status, 0)
        approved = approve._request(str(self.request))[1]
        self.assertIn(approved, stdout.getvalue())
        self.assertNotIn("PRIVATE KEY", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
