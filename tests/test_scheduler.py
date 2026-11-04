import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from shards_agent_os.scheduler import cancel_pending, enqueue, list_jobs, run_once

REQUEST_ID = "mcp-relay-" + "a" * 32


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "state.db"

    def add(self, *, run_at=1, tool="echo", arguments=None):
        return enqueue(
            self.db, run_at_ms=run_at, port=8765, tool=tool,
            arguments={"text": "test"} if arguments is None else arguments,
            permit_file="/tmp/operator-issued-permit.json", now_ms=0,
        )

    def test_atomic_claim_and_valid_allow(self):
        job_id = self.add()
        result = run_once(self.db, now_ms=2, runner=lambda job, timeout: (
            0, json.dumps({"decision": "ALLOW", "request_id": REQUEST_ID, "result": "test"})))
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(result["job_id"], job_id)
        self.assertIsNone(run_once(self.db, now_ms=2, runner=lambda *_: self.fail("repeated")))

    def test_kernel_denial_is_not_retried(self):
        self.add()
        result = run_once(self.db, now_ms=2, runner=lambda *_: (2, '{"decision":"DENY"}'))
        self.assertEqual(result["status"], "DENIED")
        self.assertIsNone(run_once(self.db, now_ms=2))

    def test_doubtful_outcomes_fail_closed(self):
        self.add()
        result = run_once(self.db, now_ms=2, runner=lambda *_: (0, '{"decision":"ALLOW"}'))
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(list_jobs(self.db)[0]["status"], "UNKNOWN")

    def test_timed_out_request_is_not_automatically_retried(self):
        self.add()
        def timeout(*_):
            raise subprocess.TimeoutExpired("kernel", 3)
        result = run_once(self.db, now_ms=2, runner=timeout)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(run_once(self.db, now_ms=2))

    def test_cancellation_applies_only_to_pending(self):
        job_id = self.add(run_at=100)
        self.assertTrue(cancel_pending(self.db, job_id))
        self.assertFalse(cancel_pending(self.db, job_id))
        self.assertIsNone(run_once(self.db, now_ms=100))

    def test_due_time_is_observed(self):
        self.add(run_at=100)
        self.assertIsNone(run_once(self.db, now_ms=99))

    def test_bad_arguments_are_rejected(self):
        for tool, args in [("add", {"a": True, "b": 3}), ("echo", {"text": 2}), ("other", {})]:
            with self.subTest(tool=tool, args=args), self.assertRaises(ValueError):
                self.add(tool=tool, arguments=args)

    def test_private_database_mode(self):
        self.add()
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)
        os.chmod(self.db, 0o644)
        with self.assertRaises(PermissionError):
            list_jobs(self.db)

    def test_crashed_running_job_remains_unreplayable(self):
        self.add()
        conn = sqlite3.connect(self.db)
        try:
            with conn:
                conn.execute("UPDATE jobs SET status='RUNNING'")
        finally:
            conn.close()
        self.assertIsNone(run_once(self.db, now_ms=100))
        self.assertEqual(list_jobs(self.db)[0]["status"], "RUNNING")


if __name__ == "__main__":
    unittest.main()
