"""Durable-harness regression tests using the real Agent OS SQLite store."""
from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from shards_agent_os.harness import (
    create_task, get_task, list_tasks, refresh_task, release_step,
)
from shards_agent_os.harness_cli import main
from shards_agent_os.interrupts import halt
from shards_agent_os.storage import open_db


STEPS = [
    {"port": 8765, "tool": "echo", "arguments": {"text": "hello"}},
    {"port": 8765, "tool": "add", "arguments": {"a": 2, "b": 3}},
]


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        os.chmod(self.directory.name, 0o700)
        self.db = str(Path(self.directory.name) / "agent-os.sqlite")

    def create(self, steps=None):
        return create_task(self.db, name="test plan", steps=STEPS if steps is None else steps)

    def mark(self, job_id, status):
        with open_db(self.db) as conn:
            conn.execute("UPDATE jobs SET status=? WHERE job_id=?", (status, job_id))

    def test_persistence_and_no_implicit_execution(self):
        task = self.create()
        self.assertEqual(get_task(self.db, task)["status"], "WAITING_PERMIT")
        self.assertEqual(len(list_tasks(self.db)), 1)
        with open_db(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)
        self.assertEqual(refresh_task(self.db, task)["status"], "WAITING_PERMIT")

    def test_sequential_progress(self):
        task = self.create()
        first = release_step(self.db, task_id=task, ordinal=0, permit_file="/private/permit-a.json")
        self.assertEqual(get_task(self.db, task)["status"], "QUEUED")
        with self.assertRaises(ValueError):
            release_step(self.db, task_id=task, ordinal=1, permit_file="/private/permit-b.json")
        self.mark(first, "RUNNING")
        self.assertEqual(refresh_task(self.db, task)["status"], "RUNNING")
        self.mark(first, "SUCCEEDED")
        self.assertEqual(refresh_task(self.db, task)["status"], "WAITING_PERMIT")
        second = release_step(self.db, task_id=task, ordinal=1, permit_file="/private/permit-b.json")
        self.mark(second, "SUCCEEDED")
        result = refresh_task(self.db, task)
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual([s["status"] for s in result["steps"]], ["SUCCEEDED", "SUCCEEDED"])

    def test_duplicate_dispatch_is_rejected(self):
        task = self.create()
        release_step(self.db, task_id=task, ordinal=0, permit_file="/private/permit-a.json")
        with self.assertRaises(ValueError):
            release_step(self.db, task_id=task, ordinal=0, permit_file="/private/permit-b.json")
        with open_db(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)

    def test_concurrent_claims_only_enqueue_once(self):
        task = self.create()
        barrier = threading.Barrier(2)
        results = []
        def invoke():
            barrier.wait()
            try:
                results.append(release_step(self.db, task_id=task, ordinal=0,
                                            permit_file="/private/concurrent.json"))
            except ValueError:
                results.append("refused")
        threads = [threading.Thread(target=invoke) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        self.assertEqual(len(results), 2)
        self.assertEqual(results.count("refused"), 1)
        with open_db(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)

    def test_unknown_denied_cancelled_all_stop_progression(self):
        for status in ("DENIED", "UNKNOWN", "CANCELLED"):
            with self.subTest(status=status):
                task = self.create()
                job = release_step(self.db, task_id=task, ordinal=0,
                                   permit_file=f"/private/{status}.json")
                self.mark(job, status)
                self.assertEqual(refresh_task(self.db, task)["status"], status)
                with self.assertRaises(ValueError):
                    release_step(self.db, task_id=task, ordinal=1,
                                 permit_file=f"/private/later-{status}.json")

    def test_missing_or_corrupt_job_blocks_replay(self):
        for case in ("missing", "invalid"):
            with self.subTest(case=case):
                task = self.create()
                job = release_step(self.db, task_id=task, ordinal=0,
                                   permit_file=f"/private/{case}.json")
                with open_db(self.db) as conn:
                    if case == "missing":
                        conn.execute("DELETE FROM jobs WHERE job_id=?", (job,))
                    else:
                        conn.execute("UPDATE jobs SET status='FUTURE_INVALID' WHERE job_id=?", (job,))
                self.assertEqual(refresh_task(self.db, task)["status"], "UNKNOWN")
                with self.assertRaises(ValueError):
                    release_step(self.db, task_id=task, ordinal=0,
                                 permit_file="/private/attempt-replay.json")

    def test_halt_prevents_release(self):
        task = self.create()
        halt(self.db, "scheduled maintenance")
        with self.assertRaises(ValueError):
            release_step(self.db, task_id=task, ordinal=0, permit_file="/private/a.json")

    def test_permit_path_cannot_be_reused(self):
        task = self.create()
        first = release_step(self.db, task_id=task, ordinal=0, permit_file="/private/reused.json")
        self.mark(first, "SUCCEEDED")
        refresh_task(self.db, task)
        with self.assertRaises(ValueError):
            release_step(self.db, task_id=task, ordinal=1, permit_file="/private/reused.json")

    def test_no_implicit_permission_without_permit_path(self):
        task = self.create()
        for path in ("", "relative.json", None):
            with self.subTest(path=path), self.assertRaises(ValueError):
                release_step(self.db, task_id=task, ordinal=0, permit_file=path)
        self.assertEqual(get_task(self.db, task)["status"], "WAITING_PERMIT")

    def test_unrecognised_steps_fail_closed(self):
        invalid = [
            [], STEPS * 17,
            [{"tool": "shell", "port": 8765, "arguments": {}}],
            [{"tool": "echo", "port": 8765, "arguments": {"text": "hi", "extra": "no"}}],
            [{"tool": "echo", "port": True, "arguments": {"text": "hi"}}],
            [{"tool": "add", "port": 8765, "arguments": {"a": True, "b": 1}}],
        ]
        for steps in invalid:
            with self.subTest(steps=steps), self.assertRaises(ValueError):
                self.create(steps)

    def test_snapshot_does_not_expose_permit_path(self):
        task = self.create()
        release_step(self.db, task_id=task, ordinal=0,
                     permit_file="/private/sensitive-permit-location.json")
        snapshot = json.dumps(get_task(self.db, task))
        self.assertNotIn("sensitive-permit-location", snapshot)
        self.assertNotIn("arguments_json", snapshot)

    def test_cli_invalid_json_and_happy_path(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--db", self.db, "create", "--name", "run",
                         "--steps-json", json.dumps(STEPS)])
        self.assertEqual(code, 0)
        task = json.loads(output.getvalue())
        self.assertEqual(task["status"], "WAITING_PERMIT")
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--db", self.db, "create", "--name", "run",
                         "--steps-json", '[{"tool":"echo","tool":"add"}]'])
        self.assertEqual(code, 2)
        self.assertIn('"ERROR"', output.getvalue())


if __name__ == "__main__":
    unittest.main()
