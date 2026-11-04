"""End-to-end harness: two independently signed permits, two agents, one task."""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from shards_agent_os.harness import create_task, get_task, refresh_task, release_step
from shards_agent_os.scheduler import run_once

DEPENDENCIES = all(importlib.util.find_spec(m) is not None
                   for m in ("shards_kernel", "cryptography", "mcp"))


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(os.name == "posix" and DEPENDENCIES, "Requires POSIX, Shards-Kernel, MCP and cryptography")
class LiveHarnessIntegration(unittest.TestCase):
    def test_two_signed_agents_sequentially_finish_task(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from shards_kernel.integrations.auth import agent_token_kdf
        from shards_kernel.integrations.wire import permit_to_mapping
        from shards_kernel.issuer import sign_operator_policy, sign_v2_permit
        from shards_kernel.permits import PermitBuilder

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            operator_key = Ed25519PrivateKey.generate()
            issuer_key = Ed25519PrivateKey.generate()
            pepper = secrets.token_urlsafe(48)
            alpha = "agent-alpha." + secrets.token_urlsafe(48)
            beta = "agent-beta." + secrets.token_urlsafe(48)
            port = free_port()
            now = int(time.time() * 1000)
            policy_data = {
                "version": 2, "kernel_id": "harness-ci-local", "tools": ["echo", "add"],
                "agents": [
                    {"actor": "agent-alpha", "token_scrypt": agent_token_kdf(alpha, pepper.encode()),
                     "allowed_tools": ["echo"]},
                    {"actor": "agent-beta", "token_scrypt": agent_token_kdf(beta, pepper.encode()),
                     "allowed_tools": ["add"]},
                ],
                "issuer_keys": [{"key_id": "permit-issuer", "issuer": "operator",
                                 "public_key_hex": issuer_key.public_key().public_bytes_raw().hex(),
                                 "revoked": False}],
                "audit_db": str(root / "kernel_audit.sqlite3"), "port": port,
            }
            policy = sign_operator_policy(policy_data, operator_key, revision=1,
                                          issued_at_ms=now-60000, expires_at_ms=now+600000)
            policy_path = root / "signed-operator.json"
            policy_path.write_text(json.dumps(policy))

            def permit(actor, tool, args, filename):
                candidate = (PermitBuilder().issuer("operator").subject(actor)
                             .jurisdiction("default").action(tool).params(args)
                             .max_executions(1).valid_from_ms(now-30000)
                             .valid_until_ms(now+180000)
                             .proposal_hash("test-approved-" + actor + "-" + tool)
                             .build_unsigned_v2(key_id="permit-issuer", audience="harness-ci-local"))
                signed = permit_to_mapping(sign_v2_permit(candidate, issuer_key))
                target = root / filename
                fd = os.open(target, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as handle:
                    json.dump(signed, handle)
                return str(target)

            echo_permit = permit("agent-alpha", "echo", {"text": "harness-e2e"}, "echo.json")
            add_permit = permit("agent-beta", "add", {"a": 2, "b": 3}, "add.json")
            env = os.environ.copy()
            env.update({
                "SHARDS_KERNEL_API_KEY": secrets.token_urlsafe(48),
                "SHARDS_KERNEL_AGENT_AUTH_PEPPER": pepper,
                "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX": operator_key.public_key().public_bytes_raw().hex(),
            })
            process = subprocess.Popen(
                [sys.executable, "-m", "shards_kernel", "serve", "--config", str(policy_path)],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                healthy = False
                for _ in range(120):
                    if process.poll() is not None:
                        break
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.3) as response:
                            if response.status == 200 and json.loads(response.read()).get("status") == "healthy":
                                healthy = True
                                break
                    except (OSError, ValueError, urllib.error.URLError):
                        pass
                    time.sleep(0.1)
                self.assertTrue(healthy, "Signed operator never reached healthy state")

                db = str(root / "agent-os.sqlite3")
                task = create_task(db, name="kernel-governed two-stage task", steps=[
                    {"port": port, "tool": "echo", "arguments": {"text": "harness-e2e"}},
                    {"port": port, "tool": "add", "arguments": {"a": 2, "b": 3}},
                ])
                self.assertEqual(get_task(db, task)["status"], "WAITING_PERMIT")
                first = release_step(db, task_id=task, ordinal=0, permit_file=echo_permit)
                with patch.dict(os.environ, {"SHARDS_KERNEL_AGENT_TOKEN": alpha}):
                    first_result = run_once(db, timeout_s=20)
                self.assertEqual(first_result["job_id"], first)
                self.assertEqual(first_result["status"], "SUCCEEDED", first_result)
                self.assertEqual(refresh_task(db, task)["status"], "WAITING_PERMIT")
                second = release_step(db, task_id=task, ordinal=1, permit_file=add_permit)
                with patch.dict(os.environ, {"SHARDS_KERNEL_AGENT_TOKEN": beta}):
                    second_result = run_once(db, timeout_s=20)
                self.assertEqual(second_result["job_id"], second)
                self.assertEqual(second_result["status"], "SUCCEEDED", second_result)
                self.assertEqual(second_result["receipt"]["result"], 5)
                self.assertEqual(refresh_task(db, task)["status"], "SUCCEEDED")
                # A fresh opening of the same database recovers completed stages.
                self.assertEqual([s["status"] for s in get_task(db, task)["steps"]],
                                 ["SUCCEEDED", "SUCCEEDED"])
                with self.assertRaises(ValueError):
                    release_step(db, task_id=task, ordinal=1, permit_file=add_permit)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=8)
