"""Fail-closed bootstrap/doctor contract, including a packaged unit byte check."""
from __future__ import annotations

import contextlib
import importlib.resources
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from shards_agent_os import host_bootstrap as boot
from shards_agent_os import host_doctor as doctor


class HostBootstrapTests(unittest.TestCase):
    def test_packaged_unit_identical_to_operator_reviewed_template(self):
        packaged = importlib.resources.files("shards_agent_os").joinpath(
            "resources/shards-agent-os-broker.service"
        ).read_bytes()
        reviewed = (
            Path(__file__).resolve().parents[1]
            / "deploy/systemd/shards-agent-os-broker.service"
        ).read_bytes()
        self.assertEqual(packaged, reviewed)
        self.assertIn(b"SupplementaryGroups=docker", packaged)
        self.assertIn(b"RuntimeDirectoryMode=0750", packaged)
        self.assertIn(b"StateDirectoryMode=0700", packaged)

    def test_plan_never_changes_host(self):
        output = io.StringIO()
        with patch.object(boot, "bootstrap") as handler, contextlib.redirect_stdout(output):
            self.assertEqual(boot.main(["--agent-user", "shards-agent"]), 0)
        handler.assert_not_called()
        self.assertIn("PLAN ONLY", output.getvalue())

    def test_apply_requires_acknowledgement(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            boot.main(["--agent-user", "shards-agent", "--apply"])
        self.assertEqual(caught.exception.code, 2)

    def test_start_without_apply_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            boot.main(["--agent-user", "shards-agent", "--start"])
        self.assertEqual(caught.exception.code, 2)

    def test_precondition_failure_does_not_provision_identities(self):
        with (
            patch.object(boot, "_preconditions", side_effect=PermissionError("test")),
            patch.object(boot, "_ensure_host_accounts") as account,
            patch.object(boot, "_install_unit") as install,
        ):
            with self.assertRaisesRegex(boot.BootstrapFailure, "prerequisites:PermissionError"):
                boot.bootstrap("shards-agent", start=True)
            account.assert_not_called()
            install.assert_not_called()

    def test_bootstrap_requires_doctor_before_service_activation(self):
        checks = [doctor.Check("pinned_key", True, "okay")]
        call_order = []
        with (
            patch.object(boot, "_preconditions", side_effect=lambda *_: call_order.append("preconditions")),
            patch.object(boot, "_ensure_host_accounts", side_effect=lambda *_: call_order.append("accounts")),
            patch.object(boot, "_install_unit", side_effect=lambda: call_order.append("unit")),
            patch.object(boot, "_run", side_effect=lambda *_: call_order.append("systemctl")),
            patch.object(boot.host_doctor, "inspect_host", return_value=checks) as inspect,
        ):
            boot.bootstrap("shards-agent", start=True)
        self.assertEqual(call_order, [
            "preconditions", "accounts", "unit", "systemctl", "systemctl"
        ])
        self.assertEqual(inspect.call_count, 2)
        self.assertTrue(inspect.call_args_list[-1].kwargs["running"])

    def test_failed_doctor_prevents_service_start(self):
        checks = [doctor.Check("docker_runsc", False, "not registered")]
        with (
            patch.object(boot, "_preconditions"),
            patch.object(boot, "_ensure_host_accounts"),
            patch.object(boot, "_install_unit"),
            patch.object(boot, "_run") as command,
            patch.object(boot.host_doctor, "inspect_host", return_value=checks),
        ):
            with self.assertRaises(RuntimeError):
                boot.bootstrap("shards-agent", start=True)
            command.assert_not_called()

    def test_apply_does_not_claim_success_after_error(self):
        stderr = io.StringIO()
        with patch.object(boot, "bootstrap", side_effect=RuntimeError("secret-path-leak")):
            with contextlib.redirect_stderr(stderr):
                result = boot.main([
                    "--agent-user", "shards-agent",
                    "--apply", "--acknowledge-rootful-docker",
                ])
        self.assertEqual(result, 2)
        self.assertNotIn("secret-path-leak", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
