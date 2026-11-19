"""Offline regression tests for the read-only recovery report.

These exercise only durable SQLite state. No kernel, broker or network call is
made, and every test asserts that producing a report never mutates a job.
"""
from __future__ import annotations

from contextlib import closing

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from shards_agent_os.recovery_report import build_recovery_report
from shards_agent_os.sandbox_jobs import enqueue_sandbox, run_sandbox_once
from shards_agent_os.scheduler import enqueue, run_once
from shards_agent_os.storage import open_db

REQUEST_ID = "mcp-relay-" + "a" * 32
CANARY = "CANARY-8f3a1c-DO-NOT-ECHO"
IMAGE = "busybox@sha256:" + "b" * 64
OPERATOR_UID = os.geteuid() + 200


def _sandbox_params(secret: str = "signed-sandbox-work") -> dict:
    return {
        "image": IMAGE,
        "argv": ["/bin/echo", secret],
        "timeout_seconds": 20,
        "memory_megabytes": 256,
        "cpu_millicores": 500,
        "pids_limit": 32,
    }


def _sandbox_result(arguments: dict) -> dict:
    from shards_agent_os.sandbox_executor import ExecutionSpec

    fingerprint = ExecutionSpec(
        image=arguments["image"], argv=tuple(arguments["argv"]),
        timeout_seconds=arguments["timeout_seconds"],
        memory_megabytes=arguments["memory_megabytes"],
        cpu_millicores=arguments["cpu_millicores"],
        pids_limit=arguments["pids_limit"],
    ).fingerprint()
    return {
        "decision": "ALLOW",
        "result": {
            "status": "EXITED", "exit_code": 0,
            "stdout": "signed-sandbox-work\n", "stderr": "", "duration_ms": 11,
            "fingerprint": fingerprint, "cleanup_confirmed": True,
        },
    }


class RecoveryReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "state.db"

    def add(self, *, run_at=1, tool="echo", arguments=None):
        return enqueue(
            self.db, run_at_ms=run_at, port=8765, tool=tool,
            arguments={"text": "test"} if arguments is None else arguments,
            permit_file="/private/operator-permit.json", now_ms=0,
        )

    def _fingerprint(self) -> tuple:
        info = self.db.stat()
        return (info.st_ino, info.st_mtime_ns, info.st_size)

    def _raw_status(self, job_id: str) -> str:
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute(
                "SELECT status FROM jobs WHERE job_id=?", (job_id,)
            ).fetchone()[0]
        finally:
            conn.close()

    def _set_running(self, job_id: str) -> None:
        conn = sqlite3.connect(self.db)
        try:
            with conn:
                conn.execute(
                    "UPDATE jobs SET status='RUNNING', started_at_ms=1 WHERE job_id=?",
                    (job_id,),
                )
        finally:
            conn.close()

    def test_completed_job_produces_accurate_receipt(self):
        job_id = self.add()
        run_once(self.db, now_ms=2, runner=lambda job, timeout: (
            0, json.dumps({"decision": "ALLOW", "request_id": REQUEST_ID,
                           "result": "test"})))
        report = build_recovery_report(self.db, job_id, now_ms=3)
        self.assertTrue(report["found"])
        self.assertEqual(report["execution_category"], "mcp_tool_job")
        self.assertEqual(report["durable_state"], "SUCCEEDED")
        self.assertEqual(report["completion"], "VERIFIED")
        self.assertFalse(report["manual_reconciliation_required"])
        self.assertEqual(report["evidence_reference"]["request_id"], REQUEST_ID)
        # A recorded SUCCEEDED is not independent proof of external effects.
        self.assertFalse(report["external_effects_verified"])
        for key in ("created_at_ms", "started_at_ms", "finished_at_ms"):
            self.assertIn(key, report["recorded_timestamps"])

    def test_interrupted_running_job_remains_unresolved(self):
        job_id = self.add()
        self._set_running(job_id)
        report = build_recovery_report(self.db, job_id)
        self.assertEqual(report["durable_state"], "RUNNING")
        self.assertEqual(report["completion"], "UNRESOLVED")
        self.assertTrue(report["manual_reconciliation_required"])
        # A durable RUNNING record is never reported as a live process.
        self.assertFalse(report["live_process_observed"])
        self.assertFalse(report["durable_state_is_live_process_proof"])

    def test_unknown_job_is_not_silently_retried(self):
        job_id = self.add()
        run_once(self.db, now_ms=2, runner=lambda *_: (0, '{"decision":"ALLOW"}'))
        self.assertEqual(self._raw_status(job_id), "UNKNOWN")
        before = self._fingerprint()
        report = build_recovery_report(self.db, job_id)
        self.assertEqual(report["durable_state"], "UNKNOWN")
        self.assertEqual(report["completion"], "UNKNOWN")
        self.assertTrue(report["manual_reconciliation_required"])
        self.assertEqual(self._fingerprint(), before)
        self.assertEqual(self._raw_status(job_id), "UNKNOWN")
        # Still not claimable afterwards.
        self.assertIsNone(run_once(self.db, now_ms=100))

    def test_missing_job_id_is_explicit_not_found(self):
        self.add()
        report = build_recovery_report(self.db, "f" * 32)
        self.assertFalse(report["found"])
        self.assertEqual(report["durable_state"], "NOT_FOUND")
        self.assertEqual(report["reason"], "no_durable_record")
        self.assertIsNone(report["execution_category"])

    def test_malformed_job_id_is_rejected_without_error(self):
        self.add()
        for bad in ("", "not-a-job", "A" * 32, "../etc/passwd", None, 12345):
            with self.subTest(job_id=bad):
                report = build_recovery_report(self.db, bad)
                self.assertFalse(report["found"])
                self.assertEqual(report["reason"], "malformed_job_id")

    def test_absent_database_reports_not_found(self):
        report = build_recovery_report(self.db, "a" * 32)
        self.assertFalse(report["found"])
        self.assertEqual(report["reason"], "database_absent")

    def test_corrupt_database_reports_unreadable(self):
        self.db.write_bytes(b"not a sqlite database")
        os.chmod(self.db, 0o600)
        report = build_recovery_report(self.db, "a" * 32)
        self.assertFalse(report["found"])
        self.assertEqual(report["durable_state"], "UNREADABLE")
        self.assertEqual(report["reason"], "unreadable_database")
        self.assertTrue(report["manual_reconciliation_required"])

    def test_sensitive_information_is_absent(self):
        job_id = self.add(arguments={"text": CANARY})
        run_once(self.db, now_ms=2, runner=lambda job, timeout: (
            0, json.dumps({"decision": "ALLOW", "request_id": REQUEST_ID,
                           "result": CANARY})))
        sandbox_id = enqueue_sandbox(
            self.db, run_at_ms=1, arguments=_sandbox_params(CANARY),
            permit_file="/private/sandbox-permit.json",
            operator_uid=OPERATOR_UID, now_ms=0,
        )
        run_sandbox_once(self.db, now_ms=2, runner=lambda job, _: _sandbox_result(job.arguments))
        for job, secret in ((job_id, "operator-permit.json"), (sandbox_id, "sandbox-permit.json")):
            with self.subTest(job=job):
                encoded = json.dumps(build_recovery_report(self.db, job))
                self.assertNotIn(CANARY, encoded)
                self.assertNotIn(secret, encoded)
                self.assertNotIn("/private/", encoded)
                self.assertNotIn("signed-sandbox-work", encoded)
                self.assertNotIn("permit_file", encoded)
                self.assertNotIn("socket_path", encoded)

    def test_report_generation_does_not_mutate_state_or_schedule(self):
        job_id = self.add()
        run_once(self.db, now_ms=2, runner=lambda job, timeout: (
            0, json.dumps({"decision": "ALLOW", "request_id": REQUEST_ID,
                           "result": "test"})))
        before = self._fingerprint()
        for _ in range(3):
            build_recovery_report(self.db, job_id)
        self.assertEqual(self._fingerprint(), before)
        self.assertEqual(self._raw_status(job_id), "SUCCEEDED")
        # Nothing became claimable as a side effect.
        self.assertIsNone(run_once(self.db, now_ms=100))

    def test_denied_and_pending_are_reported_without_retry(self):
        denied = self.add()
        run_once(self.db, now_ms=2, runner=lambda *_: (2, '{"decision":"DENY"}'))
        self.assertEqual(self._raw_status(denied), "DENIED")
        report = build_recovery_report(self.db, denied)
        self.assertEqual(report["completion"], "NOT_COMPLETED")
        self.assertFalse(report["manual_reconciliation_required"])
        pending = self.add(run_at=100)
        pending_report = build_recovery_report(self.db, pending)
        self.assertEqual(pending_report["durable_state"], "PENDING")
        self.assertEqual(pending_report["completion"], "UNRESOLVED")
        self.assertEqual(self._raw_status(pending), "PENDING")

    def test_read_only_open_refuses_loose_database_mode(self):
        job_id = self.add()
        os.chmod(self.db, 0o644)
        with self.assertRaises(PermissionError):
            build_recovery_report(self.db, job_id)

    def _corrupt(self, sql: str, params: tuple) -> None:
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(sql, params)

    def test_unrepresentable_timestamp_fails_safe(self):
        job_id = self.add()
        self._corrupt(
            "UPDATE jobs SET status='SUCCEEDED', finished_at_ms=? WHERE job_id=?",
            (2 ** 62, job_id),
        )
        report = build_recovery_report(self.db, job_id)
        stamp = report["recorded_timestamps"]["finished_at_ms"]
        self.assertEqual(stamp["ms"], 2 ** 62)
        self.assertIsNone(stamp["utc"])
        self.assertFalse(stamp["utc_representable"])

        self._corrupt(
            "UPDATE jobs SET finished_at_ms=? WHERE job_id=?", (-(2 ** 62), job_id)
        )
        negative = build_recovery_report(self.db, job_id)
        self.assertIsNone(negative["recorded_timestamps"]["finished_at_ms"]["utc"])

    def test_oversized_receipt_is_reported_not_exported(self):
        job_id = self.add()
        self._corrupt(
            "UPDATE jobs SET status='UNKNOWN', result_json=? WHERE job_id=?",
            (json.dumps({"error": "A" * 500_000}), job_id),
        )
        report = build_recovery_report(self.db, job_id)
        self.assertEqual(report["evidence_reference"], {"receipt": "oversized"})
        self.assertLess(len(json.dumps(report)), 8_192)

    def test_bounded_evidence_text_keeps_incident_id(self):
        job_id = self.add()
        self._corrupt(
            "UPDATE jobs SET status='UNKNOWN', result_json=? WHERE job_id=?",
            (json.dumps({"error": "B" * 5_000, "incident_id": "INC-9"}), job_id),
        )
        evidence = build_recovery_report(self.db, job_id)["evidence_reference"]
        self.assertLessEqual(len(evidence["error"]), 512 + len("…[truncated]"))
        self.assertTrue(evidence["error"].endswith("…[truncated]"))
        self.assertEqual(evidence["incident_id"], "INC-9")

    def test_oversized_identifiers_are_bounded(self):
        job_id = self.add()
        self._corrupt("UPDATE jobs SET tool=? WHERE job_id=?", ("X" * 100_000, job_id))
        report = build_recovery_report(self.db, job_id)
        self.assertLessEqual(len(report["tool"]), 64 + len("…[truncated]"))

    def test_harness_task_reports_step_states(self):
        from shards_agent_os.harness import create_task

        task_id = create_task(self.db, name="demo", steps=[
            {"tool": "echo", "port": 8765, "arguments": {"text": "hi"}},
            {"tool": "github.list_workflow_runs", "port": 0,
             "arguments": {"repository": "Shards-foundation/Shards-Agent-OS"}},
        ])
        before = self._fingerprint()
        report = build_recovery_report(self.db, task_id)
        self.assertEqual(report["execution_category"], "harness_task")
        self.assertEqual(report["durable_state"], "WAITING_PERMIT")
        self.assertEqual(report["completion"], "NOT_STARTED")
        self.assertEqual(len(report["steps"]), 2)
        self.assertEqual(self._fingerprint(), before)



    def test_harness_partial_progress_overrides_stale_parent(self):
        from shards_agent_os.harness import create_task

        task_id = create_task(self.db, name="stale parent", steps=[
            {"tool": "echo", "port": 8765, "arguments": {"text": "first"}},
            {"tool": "echo", "port": 8765, "arguments": {"text": "second"}},
        ])
        job_id = self.add()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(
                "UPDATE jobs SET status='SUCCEEDED', result_json=? WHERE job_id=?",
                (json.dumps({"decision": "ALLOW", "request_id": REQUEST_ID,
                             "result": "test"}), job_id),
            )
            conn.execute(
                "UPDATE harness_steps SET status='QUEUED',job_id=? "
                "WHERE task_id=? AND ordinal=0", (job_id, task_id),
            )
        before = self._fingerprint()
        report = build_recovery_report(self.db, task_id)
        self.assertEqual(report["recorded_task_state"], "WAITING_PERMIT")
        self.assertEqual(report["durable_state"], "PARTIAL")
        self.assertEqual(report["completion"], "PARTIAL")
        self.assertTrue(report["partial_progress"])
        self.assertEqual(report["step_progress"], {"succeeded": 1, "total": 2})
        self.assertEqual([step["status"] for step in report["steps"]],
                         ["SUCCEEDED", "WAITING_PERMIT"])
        self.assertEqual(report["steps"][0]["recorded_step_state"], "QUEUED")
        self.assertFalse(report["manual_reconciliation_required"])
        self.assertEqual(self._fingerprint(), before)

    def test_harness_linked_running_unknown_and_missing_jobs_fail_closed(self):
        from shards_agent_os.harness import create_task

        task_id = create_task(self.db, name="uncertain task", steps=[
            {"tool": "echo", "port": 8765, "arguments": {"text": "first"}},
        ])
        job_id = self.add()
        self._set_running(job_id)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(
                "UPDATE harness_steps SET status='QUEUED',job_id=? "
                "WHERE task_id=? AND ordinal=0", (job_id, task_id),
            )
        running = build_recovery_report(self.db, task_id)
        self.assertEqual(running["durable_state"], "RUNNING")
        self.assertTrue(running["manual_reconciliation_required"])
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(
                "UPDATE jobs SET status='UNKNOWN',result_json=? WHERE job_id=?",
                (json.dumps({"error": "Execution outcome uncertain"}), job_id),
            )
        unknown = build_recovery_report(self.db, task_id)
        self.assertEqual(unknown["durable_state"], "UNKNOWN")
        self.assertTrue(unknown["manual_reconciliation_required"])
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("DELETE FROM jobs WHERE job_id=?", (job_id,))
        missing = build_recovery_report(self.db, task_id)
        self.assertEqual(missing["durable_state"], "UNKNOWN")
        self.assertTrue(missing["manual_reconciliation_required"])

    def test_unknown_receipts_preserve_bounded_error_and_incident_id(self):
        from shards_agent_os.scheduler import reconcile_unknown
        from shards_agent_os.sandbox_jobs import reconcile_sandbox_unknown

        mcp_id = self.add()
        self._set_running(mcp_id)
        self.assertTrue(reconcile_unknown(self.db, mcp_id, "INC-123"))
        mcp_receipt = build_recovery_report(self.db, mcp_id)
        self.assertEqual(mcp_receipt["evidence_reference"]["incident_id"], "INC-123")
        self.assertEqual(mcp_receipt["evidence_reference"]["error"],
                         "Operator moved RUNNING to UNKNOWN")
        self.assertTrue(mcp_receipt["manual_reconciliation_required"])

        sandbox_id = enqueue_sandbox(
            self.db, run_at_ms=1, arguments=_sandbox_params(CANARY),
            permit_file="/private/sandbox-permit.json",
            operator_uid=OPERATOR_UID, now_ms=0,
        )
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(
                "UPDATE sandbox_jobs SET status='RUNNING' WHERE job_id=?",
                (sandbox_id,),
            )
        self.assertTrue(reconcile_sandbox_unknown(
            self.db, job_id=sandbox_id, incident_id="INC-SANDBOX-123",
        ))
        receipt = build_recovery_report(self.db, sandbox_id)
        self.assertEqual(receipt["evidence_reference"]["incident_id"],
                         "INC-SANDBOX-123")
        self.assertEqual(receipt["evidence_reference"]["error"],
                         "Manually reconciled to UNKNOWN")
        self.assertNotIn(CANARY, json.dumps(receipt))


class RecoveryReportCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "state.db"
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

    def _cli(self, *parts):
        result = subprocess.run(
            [sys.executable, "-m", "shards_agent_os", "--db", str(self.db), *parts],
            env=self.env, capture_output=True, text=True, timeout=15,
        )
        return result.returncode, json.loads(result.stdout)

    def test_cli_reports_completed_job(self):
        job_id = enqueue(
            self.db, run_at_ms=1, port=8765, tool="echo",
            arguments={"text": "hello"}, permit_file="/private/permit.json", now_ms=0,
        )
        run_once(self.db, now_ms=2, runner=lambda job, timeout: (
            0, json.dumps({"decision": "ALLOW", "request_id": REQUEST_ID,
                           "result": "hello"})))
        rc, report = self._cli("recovery-report", "--job-id", job_id)
        self.assertEqual(rc, 0)
        self.assertEqual(report["completion"], "VERIFIED")
        self.assertEqual(report["durable_state"], "SUCCEEDED")

    def test_cli_reports_not_found(self):
        enqueue(self.db, run_at_ms=1, port=8765, tool="echo",
                arguments={"text": "hello"}, permit_file="/private/permit.json", now_ms=0)
        rc, report = self._cli("recovery-report", "--job-id", "f" * 32)
        self.assertEqual(rc, 0)
        self.assertFalse(report["found"])
        self.assertEqual(report["durable_state"], "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
