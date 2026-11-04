"""Read-only harness bridge regression and interruption tests."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from shards_agent_os.harness import create_task, get_task, refresh_task, release_step
from shards_agent_os.harness_read import get_read_job, release_read_step, run_read_job
from shards_agent_os.interrupts import halt


READ = {"tool": "github.list_workflow_runs", "port": 0,
        "arguments": {"repository": "Shards-foundation/Shards-kernel"}}
ROOT = "a" * 64


def valid_inspection(repo):
    report = {
        "schema": "shards-github-agent/report-v1",
        "repository": repo,
        "operation": "github.list_workflow_runs",
        "decision": "ALLOW",
        "status": "completed",
        "checked": 1,
        "needs_attention": False,
        "failures": [],
        "in_progress": [],
        "evidence_root_hash": ROOT,
        "audit_entries": 1,
        "issuer_mode": "local-ephemeral-read-only",
    }
    return report, {"root_hash": ROOT, "ledger_entries": [{"test": "fake"}]}


class ReadOnlyHarnessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.chmod(tmp.name, 0o700)
        self.db = str(Path(tmp.name) / "jobs.sqlite3")
        self.verifier = patch("shards_kernel.api.verify_evidence_bundle",
                              return_value=SimpleNamespace(is_valid=True))
        self.verifier.start()
        self.addCleanup(self.verifier.stop)

    def task(self, steps=None):
        return create_task(self.db, name="Inspect GitHub workflow health",
                           steps=[READ] if steps is None else steps)

    def test_read_only_task_records_intent_without_execution(self):
        tid = self.task()
        state = get_task(self.db, tid)
        self.assertEqual(state["status"], "WAITING_PERMIT")
        self.assertEqual(state["steps"][0]["tool"], "github.list_workflow_runs")
        with self.assertRaises(ValueError):
            release_step(self.db, task_id=tid, ordinal=0, permit_file="/private/permit.json")

    def test_claim_verify_and_persist(self):
        tid = self.task()
        job = release_read_step(self.db, task_id=tid, ordinal=0)
        self.assertEqual(refresh_task(self.db, tid)["status"], "QUEUED")
        snapshot = run_read_job(self.db, job_id=job, inspector=valid_inspection)
        self.assertEqual(snapshot["status"], "SUCCEEDED")
        self.assertEqual(get_task(self.db, tid)["status"], "SUCCEEDED")
        persisted = get_read_job(self.db, job)
        self.assertEqual(persisted["report"]["checked"], 1)
        self.assertEqual(persisted["root_hash"], ROOT)
        self.assertEqual(refresh_task(self.db, tid)["status"], "SUCCEEDED")

    def test_failed_inspection_does_not_retry_or_leak(self):
        tid = self.task()
        job = release_read_step(self.db, task_id=tid, ordinal=0)
        def failed(_):
            raise RuntimeError("SENSITIVE_BEARER_SHOULD_NOT_BE_STORED")
        result = run_read_job(self.db, job_id=job, inspector=failed)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(get_read_job(self.db, job)["report"])
        self.assertNotIn("SENSITIVE_BEARER", json.dumps(get_read_job(self.db, job)))
        with self.assertRaises(ValueError):
            run_read_job(self.db, job_id=job, inspector=valid_inspection)
        self.assertEqual(refresh_task(self.db, tid)["status"], "UNKNOWN")

    def test_mismatched_repo_and_forged_allow_denied(self):
        bad = []
        def mismatched(repo):
            report, evidence = valid_inspection(repo)
            report["repository"] = "another/repository"
            bad.append(report)
            return report, evidence
        tid = self.task()
        job = release_read_step(self.db, task_id=tid, ordinal=0)
        result = run_read_job(self.db, job_id=job, inspector=mismatched)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertNotEqual(get_read_job(self.db, job)["status"], "SUCCEEDED")

    def test_invalid_evidence_fails_closed(self):
        tid = self.task()
        job = release_read_step(self.db, task_id=tid, ordinal=0)
        def wrong_root(repo):
            report, evidence = valid_inspection(repo)
            evidence["root_hash"] = "b" * 64
            return report, evidence
        self.assertEqual(run_read_job(self.db, job_id=job, inspector=wrong_root)["status"], "UNKNOWN")

    def test_replay_verification_required(self):
        tid = self.task()
        job = release_read_step(self.db, task_id=tid, ordinal=0)
        with patch("shards_kernel.api.verify_evidence_bundle",
                   return_value=SimpleNamespace(is_valid=False)):
            self.assertEqual(run_read_job(self.db, job_id=job,
                                          inspector=valid_inspection)["status"], "UNKNOWN")

    def test_duplicate_release_is_rejected(self):
        tid = self.task()
        release_read_step(self.db, task_id=tid, ordinal=0)
        with self.assertRaises(ValueError):
            release_read_step(self.db, task_id=tid, ordinal=0)

    def test_halt_prevents_claim_and_release(self):
        tid = self.task()
        job = release_read_step(self.db, task_id=tid, ordinal=0)
        halt(self.db, "operator intervention")
        with self.assertRaises(ValueError):
            run_read_job(self.db, job_id=job, inspector=valid_inspection)

    def test_halt_prevents_first_release(self):
        tid = self.task()
        halt(self.db, "operator intervention")
        with self.assertRaises(ValueError):
            release_read_step(self.db, task_id=tid, ordinal=0)

    def test_sequential_read_stages(self):
        tid = self.task([READ, READ])
        with self.assertRaises(ValueError):
            release_read_step(self.db, task_id=tid, ordinal=1)
        job1 = release_read_step(self.db, task_id=tid, ordinal=0)
        run_read_job(self.db, job_id=job1, inspector=valid_inspection)
        self.assertEqual(refresh_task(self.db, tid)["status"], "WAITING_PERMIT")
        job2 = release_read_step(self.db, task_id=tid, ordinal=1)
        run_read_job(self.db, job_id=job2, inspector=valid_inspection)
        self.assertEqual(refresh_task(self.db, tid)["status"], "SUCCEEDED")

    def test_invalid_repository_and_exact_fields(self):
        for repository in ("../bad", "owner/../repo", "owner/.hidden",
                           "owner/", "https://github.com/owner/repo", "", 123):
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                self.task([{**READ,"arguments":{"repository":repository}}])
        with self.assertRaises(ValueError):
            self.task([{**READ, "port": 8765}])
        with self.assertRaises(ValueError):
            self.task([{**READ, "arguments": {"repository": "valid/repo", "token": "bad"}}])

    def test_read_job_persists_running_for_reconciliation(self):
        tid = self.task()
        job = release_read_step(self.db, task_id=tid, ordinal=0)
        from shards_agent_os.storage import open_db
        with open_db(self.db) as conn:
            conn.execute("UPDATE harness_read_jobs SET status='RUNNING' WHERE job_id=?", (job,))
        self.assertEqual(refresh_task(self.db, tid)["status"], "RUNNING")
        with self.assertRaises(ValueError):
            run_read_job(self.db, job_id=job, inspector=valid_inspection)

    def test_concurrent_double_claim_never_executes_twice(self):
        tid = self.task()
        job = release_read_step(self.db, task_id=tid, ordinal=0)
        event = threading.Barrier(2)
        invoked = []
        outputs = []
        def call():
            event.wait()
            def inspect(repo):
                invoked.append(repo)
                return valid_inspection(repo)
            try:
                outputs.append(run_read_job(self.db, job_id=job, inspector=inspect)["status"])
            except ValueError:
                outputs.append("REFUSED")
        threads = [threading.Thread(target=call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(len(invoked), 1)
        self.assertEqual(sorted(outputs), ["REFUSED", "SUCCEEDED"])


if __name__ == "__main__":
    unittest.main()
