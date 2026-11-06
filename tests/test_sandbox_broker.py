"""Linux Unix peer UID and signed permit -> real runsc acceptance.

Unit tests run on normal CI. The cross-UID end-to-end test runs only on a
disposable Ubuntu Actions runner with sudo and an installed gVisor runtime.
"""
from __future__ import annotations

import grp
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from shards_agent_os.sandbox_broker import (
    BrokerError, _parse_request, _peer_uid, _socket_path, _remove_stale_socket,
)
from test_sandbox_governance import exact_args
from test_sandbox_operator import ACTOR, ISSUER, KEY_ID, KERNEL_ID, scoped_permit

CLIENT = r'''
import socket,sys
path = sys.argv[1]
payload = sys.stdin.buffer.readline()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(20)
    connection.connect(path)
    connection.sendall(payload)
    result = bytearray()
    while not result.endswith(b"\n"):
        block = connection.recv(8192)
        if not block:
            break
        result.extend(block)
sys.stdout.buffer.write(result)
'''


class BrokerUnitTests(unittest.TestCase):
    def test_protocol_denies_unsigned_wrong_tool_and_actor_override(self):
        good = {"name": "sandbox.exec", "arguments": exact_args(), "permit": {"version": 2}}
        self.assertEqual(_parse_request(json.dumps(good).encode())[0], good["arguments"])
        for obj in (
            {"name": "sandbox.exec", "arguments": exact_args()},
            {"name": "echo", "arguments": exact_args(), "permit": {}},
            {**good, "actor": "operator"},
            {**good, "permit": None},
        ):
            with self.subTest(obj=obj), self.assertRaises(BrokerError):
                _parse_request(json.dumps(obj).encode())
        for raw in (
            b'{"name":"sandbox.exec","name":"sandbox.exec"}',
            b'{"name":"sandbox.exec","arguments":NaN,"permit":{}}',
            b"", b"{" * 65537,
        ):
            with self.subTest(raw=raw[:30]), self.assertRaises(BrokerError):
                _parse_request(raw)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux peer creds required")
    def test_real_unix_peer_uid_matches_kernel(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with left, right:
            self.assertEqual(_peer_uid(left), os.getuid())

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() != 0, "Unprivileged Linux required")
    def test_socket_directory_rejects_world_access_and_stale_files(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "client.sock"
            self.assertEqual(_socket_path(str(path)), path)
            os.chmod(root, 0o777)
            with self.assertRaises(PermissionError):
                _socket_path(str(path))
            os.chmod(root, 0o700)
            path.write_text("not a unix socket")
            with self.assertRaises(PermissionError):
                _remove_stale_socket(path)


@unittest.skipUnless(
    sys.platform.startswith("linux") and os.geteuid() != 0
    and os.getenv("SHARDS_SANDBOX_LIVE") == "1",
    "Explicit Linux gVisor cross-UID acceptance runner required",
)
class RealPeerCredentialBrokerTests(unittest.TestCase):
    def test_unprivileged_agent_cannot_use_docker_but_can_run_signed_sandbox(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        image = os.getenv("SHARDS_SANDBOX_IMAGE", "")
        self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
        agent = "shards-ci-agent"
        group = grp.getgrgid(os.getegid()).gr_name
        created = subprocess.run(
            ["sudo", "-n", "useradd", "--system", "--no-create-home",
             "--gid", group, agent],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        agent_uid = int(subprocess.check_output(["id", "-u", agent], text=True).strip())

        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o750)
            path = Path(root)
            socket_dir = path / "socket"
            socket_dir.mkdir(mode=0o750)
            state_dir = path / "state"
            state_dir.mkdir(mode=0o700)
            audit = state_dir / "kernel.sqlite3"
            sock_path = socket_dir / "sandbox.sock"
            key = Ed25519PrivateKey.generate()
            cmd = [
                sys.executable, "-m", "shards_agent_os.sandbox_broker",
                "--socket", str(sock_path),
                "--peer-uid", str(agent_uid),
                "--kernel-id", KERNEL_ID,
                "--actor", ACTOR,
                "--audit-db", str(audit),
                "--issuer", ISSUER,
                "--key-id", KEY_ID,
                "--public-key-hex", key.public_key().public_bytes_raw().hex(),
            ]
            args = exact_args(image=image)
            permit = scoped_permit(key, args)
            request = json.dumps({
                "name": "sandbox.exec", "arguments": args, "permit": permit,
            }, separators=(",", ":")) + "\n"

            def start():
                process = subprocess.Popen(
                    cmd, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    close_fds=True,
                )
                for _ in range(150):
                    if sock_path.is_socket():
                        return process
                    if process.poll() is not None:
                        error = process.communicate(timeout=2)[1].decode(errors="replace")
                        self.fail(f"Broker exited before listening: {error[:400]}")
                    time.sleep(0.1)
                self.fail("Broker never created its local Unix socket")

            def call_as_agent(data):
                result = subprocess.run(
                    ["sudo", "-n", "-u", agent, "/usr/bin/python3",
                     "-c", CLIENT, str(sock_path)],
                    input=data, capture_output=True, text=True,
                    timeout=25, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)

            first = start()
            second = None
            try:
                # The unprivileged caller must not have the privileged daemon
                # interface that the operator holds.
                denied = subprocess.run(
                    ["sudo", "-n", "-u", agent, "/usr/bin/python3", "-c",
                     "import socket; s=socket.socket(socket.AF_UNIX); "
                     "s.connect('/var/run/docker.sock')"],
                    capture_output=True, timeout=10, check=False,
                )
                self.assertNotEqual(denied.returncode, 0)

                # Same-user operator processes cannot claim to be the agent.
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as caller:
                    caller.settimeout(5)
                    caller.connect(str(sock_path))
                    response = caller.recv(4096).decode()
                self.assertEqual(json.loads(response)["decision"], "DENY")

                result = call_as_agent(request)
                self.assertEqual(result["decision"], "ALLOW", result)
                self.assertEqual(result["result"]["status"], "EXITED")
                self.assertEqual(result["result"]["stdout"].strip(), "accepted")
                self.assertTrue(result["result"]["cleanup_confirmed"])

                # Abrupt crash: stale Unix path persists, audit state persists,
                # but permit consumption prevents execution on another boot.
                first.kill()
                first.wait(timeout=10)
                second = start()
                replay = call_as_agent(request)
                self.assertEqual(replay["decision"], "DENY", replay)
                self.assertTrue(audit.exists())
                self.assertEqual(stat.S_IMODE(audit.stat().st_mode), 0o600)
            finally:
                for proc in (second, first):
                    if proc is not None and proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=8)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=8)


if __name__ == "__main__":
    unittest.main()
