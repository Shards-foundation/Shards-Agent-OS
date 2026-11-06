"""Proof-oriented tests for the gVisor OCI runtime boundary.

Unit tests run everywhere; real Docker/runsc tests run only when explicitly
enabled on an ephemeral, trusted Linux CI runner with a preloaded image digest.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch
import subprocess

from shards_agent_os.sandbox_executor import (
    ExecutionSpec, GVisorExecutor, SandboxUnavailable,
)

DIGEST_IMAGE = "busybox@sha256:" + "a" * 64


def spec(**overrides):
    settings = {"image": DIGEST_IMAGE, "argv": ("/bin/echo", "isolated")}
    settings.update(overrides)
    return ExecutionSpec(**settings)


class GVisorUnitTests(unittest.TestCase):
    def test_must_pin_image_by_digest(self):
        for image in ("busybox:latest", "busybox:1.36", "", "busybox@sha256:abc",
                      "busybox@sha256:" + "g" * 64, "--privileged", "busybox\n"):
            with self.subTest(image=image), self.assertRaises(ValueError):
                spec(image=image)

    def test_rejects_noncanonical_commands_and_quotas(self):
        bad = (
            {"argv": ("echo", "bad\nvalue")},
            {"argv": ("echo", "\x00")},
            {"argv": []},
            {"argv": ("echo", "x" * 1025)},
            {"timeout_seconds": True},
            {"timeout_seconds": 0},
            {"timeout_seconds": 121},
            {"memory_megabytes": 0},
            {"cpu_millicores": 0},
            {"pids_limit": 0},
        )
        for values in bad:
            with self.subTest(values=values), self.assertRaises(ValueError):
                spec(**values)

    def test_fingerprint_binds_entire_execution(self):
        baseline = spec().fingerprint()
        self.assertRegex(baseline, r"^[0-9a-f]{64}$")
        self.assertEqual(baseline, spec().fingerprint())
        for change in ({"argv": ("/bin/echo", "other")},
                       {"image": "busybox@sha256:" + "b" * 64},
                       {"timeout_seconds": 30},
                       {"cpu_millicores": 700},
                       {"memory_megabytes": 512},
                       {"pids_limit": 64}):
            self.assertNotEqual(baseline, spec(**change).fingerprint())

    def test_runtime_flags_are_fixed_and_unprivileged(self):
        executor = GVisorExecutor(docker_binary="/usr/bin/docker")
        cmd = executor._command(spec(), "shards-sbx-test")
        joined = " ".join(cmd)
        self.assertIn("--runtime=runsc", cmd)
        self.assertIn("--pull=never", cmd)
        self.assertIn("--network=none", cmd)
        self.assertIn("--read-only", cmd)
        self.assertIn("--cap-drop=ALL", cmd)
        self.assertIn("no-new-privileges", cmd)
        self.assertIn("--pids-limit", cmd)
        self.assertIn("--memory-swap", cmd)
        self.assertIn("65532:65532", cmd)
        self.assertNotIn("--privileged", cmd)
        self.assertNotIn("--mount", cmd)
        self.assertNotIn("--volume", cmd)
        self.assertNotIn("--network=host", cmd)
        self.assertNotIn("--pull=always", cmd)
        self.assertEqual(cmd[-3:], [DIGEST_IMAGE, "/bin/echo", "isolated"])
        self.assertIn("unix:///var/run/docker.sock", joined)

    def test_missing_runsc_is_not_a_fallback(self):
        runner = GVisorExecutor(docker_binary="/usr/bin/docker")
        with patch("shards_agent_os.sandbox_executor.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, '{"runc":{}}', "")):
            with self.assertRaisesRegex(SandboxUnavailable, "runsc"):
                runner._preflight({"PATH": "/usr/bin:/bin"})

    def test_unknown_object_cannot_be_launched(self):
        runner = GVisorExecutor(docker_binary="/usr/bin/docker")
        with self.assertRaises(TypeError):
            runner.run({"image": DIGEST_IMAGE})

    def test_preflight_never_inherits_docker_host(self):
        runner = GVisorExecutor(docker_binary="/usr/bin/docker")
        with patch("shards_agent_os.sandbox_executor.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, '{"runsc":{}}', "")) as invoked:
            runner._preflight({"PATH": "/usr/bin:/bin"})
        argv = invoked.call_args.args[0]
        self.assertEqual(argv[:3], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"])


@unittest.skipUnless(
    sys.platform.startswith("linux") and os.getenv("SHARDS_SANDBOX_LIVE") == "1",
    "Real sandbox tests require explicit SHARDS_SANDBOX_LIVE=1 on Linux",
)
class GVisorRealProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        image = os.getenv("SHARDS_SANDBOX_IMAGE", "")
        if not image:
            raise RuntimeError("Set SHARDS_SANDBOX_IMAGE to a preloaded sha256 digest")
        cls.image = image
        cls.executor = GVisorExecutor()

    def check_run(self, argv, **limits):
        return self.executor.run(ExecutionSpec(image=self.image, argv=tuple(argv), **limits))

    def test_real_isolated_execution(self):
        result = self.check_run(("/bin/echo", "sandbox-isolated"))
        self.assertEqual(result.status, "EXITED", result)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "sandbox-isolated")
        self.assertTrue(result.cleanup_confirmed)

    def test_root_filesystem_cannot_be_modified(self):
        result = self.check_run(("/bin/sh", "-c", "touch /etc/shards-write-probe"))
        self.assertEqual(result.status, "PROCESS_ERROR", result)
        self.assertTrue(result.cleanup_confirmed)

    def test_external_network_unavailable(self):
        result = self.check_run(("/bin/sh", "-c", "wget -q -T 2 -O - http://1.1.1.1"))
        self.assertEqual(result.status, "PROCESS_ERROR", result)
        self.assertTrue(result.cleanup_confirmed)

    def test_process_group_timeout_and_container_removal(self):
        result = self.check_run(("/bin/sleep", "15"), timeout_seconds=1)
        self.assertEqual(result.status, "TIMEOUT", result)
        self.assertTrue(result.cleanup_confirmed)

    def test_output_flood_is_bounded_and_container_removed(self):
        result = self.check_run(("/bin/sh", "-c", "yes x"), timeout_seconds=10)
        self.assertEqual(result.status, "OUTPUT_LIMIT", result)
        self.assertLessEqual(len(result.stdout.encode()), 65536)
        self.assertTrue(result.cleanup_confirmed)


if __name__ == "__main__":
    unittest.main()
