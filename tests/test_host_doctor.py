"""Guardrail tests for the read-only Linux sandbox host preflight."""
from __future__ import annotations

import grp
import io
import json
import os
import pwd
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from shards_agent_os import host_doctor as doctor

VALID = {
    "SHARDS_AGENT_UID": "40050",
    "SHARDS_KERNEL_ID": "sandbox-pilot",
    "SHARDS_ACTOR": "agent-one",
    "SHARDS_ISSUER_ID": "separate-issuer",
    "SHARDS_KEY_ID": "approval-key",
    "SHARDS_ISSUER_PUBLIC_HEX": "a" * 64,
}


def env_bytes(mapping=VALID):
    return ("\n".join(f"{key}={value}" for key, value in mapping.items()) + "\n").encode()


class EnvironmentSchemaTests(unittest.TestCase):
    def test_valid_public_only_exact_schema(self):
        self.assertEqual(doctor._parse_environment(env_bytes()), VALID)

    def test_reject_mutable_or_ambiguous_config(self):
        examples = [
            b"",
            env_bytes() + b"SHARDS_AGENT_UID=999\n",
            env_bytes() + b"SHARDS_ISSUER_PRIVATE_HEX=deadbeef\n",
            env_bytes({**VALID, "SHARDS_AGENT_UID": "0"}),
            env_bytes({**VALID, "SHARDS_ACTOR": "user agent"}),
            env_bytes({**VALID, "SHARDS_ISSUER_PUBLIC_HEX": "zzzz"}),
            env_bytes() + b"\x00",
            env_bytes() + b"#" * 5000,
            env_bytes({key: val for key, val in VALID.items() if key != "SHARDS_KEY_ID"}),
        ]
        for raw in examples:
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                doctor._parse_environment(raw)

    def test_secure_config_file_refuses_world_readable_or_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "broker.env"
            path.write_bytes(env_bytes())
            os.chmod(path, 0o644)
            with self.assertRaises(PermissionError):
                doctor._private_root_config(path)
            os.chmod(path, 0o600)
            link = Path(temp) / "broker.link"
            link.symlink_to(path)
            with self.assertRaises(PermissionError):
                doctor._private_root_config(link)
            if os.geteuid() == 0:
                self.assertEqual(doctor._private_root_config(path), VALID)

    def test_permit_signing_key_must_never_be_in_config(self):
        for sensitive in ("PRIVATE_KEY", "SHARDS_SIGNING_KEY", "SHARDS_API_KEY"):
            with self.assertRaises(ValueError):
                doctor._parse_environment(env_bytes() + f"{sensitive}=secret\n".encode())


class HostIdentityTests(unittest.TestCase):
    def test_refuses_agent_in_docker_group(self):
        op = SimpleNamespace(pw_uid=101, pw_gid=51, pw_name="operator")
        ag = SimpleNamespace(pw_uid=102, pw_gid=52, pw_name="agent")
        client_group = SimpleNamespace(gr_gid=56)
        docker_socket = SimpleNamespace(st_gid=55, st_mode=stat.S_IFSOCK | 0o660)
        with (patch.object(doctor, "_user", side_effect=[op, ag]),
              patch.object(doctor.grp, "getgrnam", return_value=client_group),
              patch.object(doctor.os, "stat", return_value=docker_socket),
              patch.object(doctor, "_groups", side_effect=[{56, 55}, {56, 55}])):
            with self.assertRaises(PermissionError):
                doctor._identities("operator", "agent", "clients")

    def test_allows_distinct_owner_and_socket_only_client(self):
        op = SimpleNamespace(pw_uid=101, pw_gid=51, pw_name="operator")
        ag = SimpleNamespace(pw_uid=102, pw_gid=52, pw_name="agent")
        client_group = SimpleNamespace(gr_gid=56)
        docker_socket = SimpleNamespace(st_gid=55, st_mode=stat.S_IFSOCK | 0o660)
        with (patch.object(doctor, "_user", side_effect=[op, ag]),
              patch.object(doctor.grp, "getgrnam", return_value=client_group),
              patch.object(doctor.os, "stat", return_value=docker_socket),
              patch.object(doctor, "_groups", side_effect=[{56, 55}, {56}])):
            result = doctor._identities("operator", "agent", "clients")
        self.assertIn("agent denied Docker", result)


class RuntimeTests(unittest.TestCase):
    def test_gvisor_registration_mandatory(self):
        with patch.object(doctor.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, '{"runc":{}}', ""
        )):
            with self.assertRaises(RuntimeError):
                doctor._runtime()
        with patch.object(doctor.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, '{"runc":{},"runsc":{}}', ""
        )):
            self.assertIn("runsc", doctor._runtime())

    def test_json_report_has_no_config_content(self):
        captured = io.StringIO()
        with (patch.object(doctor, "inspect_host", return_value=[
            doctor.Check("docker_runsc", True, "runsc registered"),
            doctor.Check("private_issuer", False, "PermissionError"),
        ]), patch("sys.stdout", captured)):
            self.assertEqual(doctor.main(["--json"]), 2)
        value = json.loads(captured.getvalue())
        self.assertFalse(value["ok"])
        self.assertEqual([c["name"] for c in value["checks"]],
                         ["docker_runsc", "private_issuer"])
        self.assertNotIn("a" * 64, captured.getvalue())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only socket attributes")
    def test_local_socket_requires_exact_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            socket_path = Path(temp) / "broker.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                os.chmod(socket_path, 0o660)
                self.assertEqual(
                    doctor._path(socket_path, mode=0o660, owner_uid=os.getuid(),
                                 group_gid=os.getgid(), kind="socket"),
                    "Ownership and permissions verified",
                )
                os.chmod(socket_path, 0o666)
                with self.assertRaises(PermissionError):
                    doctor._path(socket_path, mode=0o660, owner_uid=os.getuid(),
                                 group_gid=os.getgid(), kind="socket")


if __name__ == "__main__":
    unittest.main()
