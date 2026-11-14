"""Regression: Android Termux MCP child requires trusted exec shim.

These tests never start a real MCP operator or issue authority.
"""
from __future__ import annotations

import os
import subprocess
import unittest
from unittest.mock import patch

from shards_agent_os.scheduler import Job, _invoke_kernel, _kernel_child_env


class TermuxChildEnvironmentTests(unittest.TestCase):
    PREFIX = "/data/data/com.termux/files/usr"

    def source(self):
        return {
            "PREFIX": self.PREFIX,
            "TERMUX__PREFIX": self.PREFIX,
            "LD_PRELOAD": self.PREFIX + "/lib/libtermux-exec.so",
            "TMPDIR": self.PREFIX + "/tmp",
            "PATH": self.PREFIX + "/bin",
            "HOME": "/data/data/com.termux/files/home",
            "SHARDS_KERNEL_AGENT_TOKEN": "agent-beta.disposable-test-token",
            "SHARDS_KERNEL_API_KEY": "must-not-leak-operator",
            "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX": "must-not-leak-policy",
            "SHARDS_KERNEL_AGENT_AUTH_PEPPER": "must-not-leak-pepper",
            "AWS_SECRET_ACCESS_KEY": "must-not-leak-third-party",
        }

    def test_termux_exec_shim_survives_minimal_environment(self):
        env = _kernel_child_env(self.source(), executable=self.PREFIX + "/bin/python3.13")
        self.assertEqual(env["LD_PRELOAD"], self.source()["LD_PRELOAD"])
        self.assertEqual(env["TMPDIR"], self.source()["TMPDIR"])
        self.assertEqual(env["SHARDS_KERNEL_AGENT_TOKEN"], self.source()["SHARDS_KERNEL_AGENT_TOKEN"])
        for name in (
            "SHARDS_KERNEL_API_KEY", "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX",
            "SHARDS_KERNEL_AGENT_AUTH_PEPPER", "AWS_SECRET_ACCESS_KEY",
            "PREFIX", "TERMUX__PREFIX",
        ):
            self.assertNotIn(name, env)

    def test_newer_termux_exec_library_name(self):
        src = self.source()
        src["LD_PRELOAD"] = self.PREFIX + "/lib/libtermux-exec-ld-preload.so"
        env = _kernel_child_env(src, executable=self.PREFIX + "/bin/python3.13")
        self.assertEqual(env["LD_PRELOAD"], src["LD_PRELOAD"])

    def test_untrusted_preload_chains_and_paths_rejected(self):
        values = (
            "/tmp/evil.so", "libtermux-exec.so",
            self.PREFIX + "/lib/libtermux-exec.so:/tmp/evil.so",
            self.PREFIX + "/lib/another.so",
        )
        for value in values:
            with self.subTest(preload=value):
                src = self.source()
                src["LD_PRELOAD"] = value
                self.assertNotIn(
                    "LD_PRELOAD",
                    _kernel_child_env(src, executable=self.PREFIX + "/bin/python3.13"),
                )

    def test_non_termux_executable_and_spoofed_prefix_rejected(self):
        self.assertNotIn(
            "LD_PRELOAD",
            _kernel_child_env(self.source(), executable="/usr/bin/python3.13"),
        )
        src = self.source()
        src["TERMUX__PREFIX"] = "/tmp/untrusted"
        src["PREFIX"] = "/tmp/untrusted"
        self.assertNotIn(
            "LD_PRELOAD",
            _kernel_child_env(src, executable="/tmp/untrusted/bin/python3"),
        )

    def test_android_user_zero_prefix_alias_matches_real_interpreter(self):
        alias = "/data/user/0/com.termux/files/usr"
        src = self.source()
        src["PREFIX"] = alias
        src["TERMUX__PREFIX"] = alias
        src["LD_PRELOAD"] = alias + "/lib/libtermux-exec.so"
        src["TMPDIR"] = alias + "/tmp"
        def fake_realpath(path):
            return path.replace("/data/user/0/com.termux/", "/data/data/com.termux/", 1)
        with patch("shards_agent_os.scheduler.os.path.realpath", side_effect=fake_realpath):
            env = _kernel_child_env(src, executable=alias + "/bin/python3.13")
        self.assertEqual(env.get("LD_PRELOAD"), src["LD_PRELOAD"])
        self.assertEqual(env.get("TMPDIR"), src["TMPDIR"])

    def test_unknown_tmpdir_not_passed_to_child(self):
        src = self.source()
        src["TMPDIR"] = "/tmp/suspicious"
        env = _kernel_child_env(src, executable=self.PREFIX + "/bin/python3.13")
        self.assertNotIn("TMPDIR", env)

    def test_linux_environment_remains_minimal(self):
        env = _kernel_child_env(
            {"LD_PRELOAD": "/tmp/evil.so", "HOME": "/home/test",
             "SHARDS_KERNEL_AGENT_TOKEN": "agent-token",
             "SHARDS_KERNEL_API_KEY": "operator-secret"},
            executable="/usr/bin/python3.13",
        )
        self.assertEqual(env, {
            "HOME": "/home/test",
            "SHARDS_KERNEL_AGENT_TOKEN": "agent-token",
        })

    def test_mcp_subprocess_receives_only_validated_environment(self):
        job = Job(
            job_id="test", run_at_ms=0, port=8765, tool="add",
            arguments={"a": 7, "b": 8}, permit_file="/operator/permit.json",
            status="RUNNING",
        )
        with (
            patch.dict(os.environ, self.source(), clear=True),
            patch("shards_agent_os.scheduler.sys.executable",
                  self.PREFIX + "/bin/python3.13"),
            patch("shards_agent_os.scheduler.subprocess.run") as child,
        ):
            child.return_value = subprocess.CompletedProcess(
                args=[], returncode=2, stdout='{"decision":"DENY"}', stderr=""
            )
            rc, output = _invoke_kernel(job, 10.0)
            self.assertEqual((rc, output), (2, '{"decision":"DENY"}'))
            self.assertFalse(child.call_args.kwargs["check"])
            self.assertFalse(child.call_args.kwargs.get("shell", False))
            passed = child.call_args.kwargs["env"]
            self.assertEqual(passed["LD_PRELOAD"], self.source()["LD_PRELOAD"])
            self.assertEqual(passed["SHARDS_KERNEL_AGENT_TOKEN"],
                             self.source()["SHARDS_KERNEL_AGENT_TOKEN"])
            self.assertNotIn("SHARDS_KERNEL_API_KEY", passed)
            self.assertNotIn("SHARDS_KERNEL_AGENT_AUTH_PEPPER", passed)


if __name__ == "__main__":
    unittest.main()
