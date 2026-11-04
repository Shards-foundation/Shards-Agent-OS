"""Durable read-only harness recovery across *real OS process boundaries*.

These tests intentionally use an independent subprocess and the same private
SQLite file. No outbound network calls or GitHub write scopes are required.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from shards_agent_os.harness import create_task, refresh_task
from shards_agent_os.harness_read import (
    get_read_evidence,
    get_read_job,
    reconcile_read_unknown,
    release_read_step,
    run_read_job,
)
from shards_agent_os.storage import open_db

STEP = {"tool": "github.list_workflow_runs", "port": 0,
        "arguments": {"repository": "Shards-foundation/Shards-kernel"}}


class DurableProcessRecoveryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        os.chmod(directory.name, 0o700)
        self.folder = Path(directory.name)
        self.db = str(self.folder / "private.sqlite3")
        self.task_id = create_task(self.db, name="Real process restart", steps=[STEP])
        self.job_id = release_read_step(self.db, task_id=self.task_id, ordinal=0)

    def _child(self, code: str):
        return subprocess.run(
            [sys.executable, "-c", code, self.db, self.job_id],
            capture_output=True, text=True, timeout=15, check=False,
        )

    def test_process_death_during_inspection_does_not_retry(self):
        child = self._child(
            "import os,sys\n"
            "from shards_agent_os.harness_read import run_read_job\n"
            "def die(repo):\n"
            "    os._exit(71)\n"
            "run_read_job(sys.argv[1],job_id=sys.argv[2],inspector=die)\n"
        )
        self.assertEqual(child.returncode, 71, child.stderr)
        self.assertEqual(get_read_job(self.db, self.job_id)["status"], "RUNNING")
        self.assertEqual(refresh_task(self.db, self.task_id)["status"], "RUNNING")
        with self.assertRaises(ValueError):
            run_read_job(
                self.db, job_id=self.job_id,
                inspector=lambda _repo: self.fail("Must not replay a crashed call"),
            )
        with self.assertRaises(ValueError):
            get_read_evidence(self.db, self.job_id)

    def test_completed_job_survives_process_exit_before_output_export(self):
        # Run the real SQLite transaction in a child, then exit without writing
        # report.json or evidence.json. Verification is patched here because
        # this case isolates persistence, not kernel cryptography.
        child = self._child(
            "import sys\n"
            "from types import SimpleNamespace\n"
            "from unittest.mock import patch\n"
            "from shards_agent_os.harness_read import run_read_job\n"
            "def inspect(repository):\n"
            "  root='a'*64\n"
            "  report={'schema':'shards-github-agent/report-v1',"
            "'operation':'github.list_workflow_runs','repository':repository,"
            "'decision':'ALLOW','status':'completed',"
            "'issuer_mode':'local-ephemeral-read-only','checked':0,"
            "'needs_attention':False,'failures':[],'in_progress':[],"
            "'evidence_root_hash':root,'audit_entries':1}\n"
            "  return report,{'root_hash':root,'ledger_entries':[{'step':'test'}]}\n"
            "with patch('shards_kernel.api.verify_evidence_bundle',"
            "return_value=SimpleNamespace(is_valid=True)):\n"
            "  result=run_read_job(sys.argv[1],job_id=sys.argv[2],inspector=inspect)\n"
            "  assert result['status']=='SUCCEEDED', result\n"
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(refresh_task(self.db, self.task_id)["status"], "SUCCEEDED")
        self.assertFalse((self.folder / "report.json").exists())
        self.assertFalse((self.folder / "evidence.json").exists())
        with patch("shards_kernel.api.verify_evidence_bundle",
                   return_value=SimpleNamespace(is_valid=True)):
            recovered = get_read_evidence(self.db, self.job_id)
        self.assertEqual(recovered["report"]["checked"], 0)
        self.assertEqual(recovered["evidence"]["root_hash"], "a" * 64)
        self.assertEqual(get_read_job(self.db, self.job_id)["status"], "SUCCEEDED")
        # Repeated read-only recovery never calls the inspector.
        with self.assertRaises(ValueError):
            run_read_job(self.db, job_id=self.job_id,
                         inspector=lambda _: self.fail("Illegal second execution"))

    def test_legacy_success_missing_bundle_fails_explicitly(self):
        with open_db(self.db) as conn:
            conn.execute(
                "UPDATE harness_read_jobs SET status='SUCCEEDED',root_hash=?,"
                "report_json='{}' WHERE job_id=?", ("a" * 64, self.job_id),
            )
        with self.assertRaisesRegex(ValueError, "missing evidence"):
            get_read_evidence(self.db, self.job_id)

    def test_recovered_bundle_rejects_corruption(self):
        from shards_agent_os.harness_read import _check_report
        report = {
            "schema": "shards-github-agent/report-v1",
            "operation": "github.list_workflow_runs",
            "repository": STEP["arguments"]["repository"],
            "decision": "ALLOW", "status": "completed",
            "issuer_mode": "local-ephemeral-read-only",
            "checked": 0, "needs_attention": False,
            "failures": [], "in_progress": [],
            "evidence_root_hash": "a" * 64, "audit_entries": 1,
        }
        evidence = {"root_hash": "a" * 64, "ledger_entries": [{"one": 1}]}
        with patch("shards_kernel.api.verify_evidence_bundle",
                   return_value=SimpleNamespace(is_valid=True)):
            encoded_report, encoded_evidence = _check_report(
                STEP["arguments"]["repository"], report, evidence,
            )
        with open_db(self.db) as conn:
            conn.execute(
                "UPDATE harness_read_jobs SET status='SUCCEEDED',"
                "report_json=?,root_hash=? WHERE job_id=?",
                (encoded_report, "a" * 64, self.job_id),
            )
            conn.execute(
                "INSERT INTO harness_read_evidence VALUES (?,?)",
                (self.job_id, encoded_evidence),
            )
            # The stored evidence is changed after the successful write;
            # its declared root no longer agrees with the report.
            conn.execute(
                "UPDATE harness_read_evidence SET evidence_json=? WHERE job_id=?",
                (json.dumps({"root_hash": "b" * 64,
                             "ledger_entries": [{"one": 1}]}), self.job_id),
            )
        with patch("shards_kernel.api.verify_evidence_bundle",
                   return_value=SimpleNamespace(is_valid=True)):
            with self.assertRaises(ValueError):
                get_read_evidence(self.db, self.job_id)


    def test_confirmed_stopped_worker_can_be_reconciled_without_replay(self):
        child = self._child(
            "import os,sys\n"
            "from shards_agent_os.harness_read import run_read_job\n"
            "def die(repo):\n"
            "    os._exit(74)\n"
            "run_read_job(sys.argv[1],job_id=sys.argv[2],inspector=die)\n"
        )
        self.assertEqual(child.returncode, 74, child.stderr)
        self.assertEqual(refresh_task(self.db, self.task_id)["status"], "RUNNING")
        # The test has confirmed the child process has exited. In production
        # this is a human-verified precondition, not an automatic action.
        self.assertTrue(reconcile_read_unknown(
            self.db, job_id=self.job_id, incident_id="incident-20261104-001"
        ))
        self.assertEqual(refresh_task(self.db, self.task_id)["status"], "UNKNOWN")
        record = get_read_job(self.db, self.job_id)
        self.assertEqual(record["status"], "UNKNOWN")
        self.assertEqual(record["incident_id"], "incident-20261104-001")
        self.assertFalse(reconcile_read_unknown(
            self.db, job_id=self.job_id, incident_id="incident-20261104-002"
        ))
        with self.assertRaises(ValueError):
            run_read_job(self.db, job_id=self.job_id,
                         inspector=lambda _: self.fail("Old job must never replay"))
        # Capacity is now available for a NEW, independent read-only task.
        next_task = create_task(self.db, name="New independent inspection", steps=[STEP])
        next_job = release_read_step(self.db, task_id=next_task, ordinal=0)
        def valid(repo):
            root = "a" * 64
            return ({
                "schema": "shards-github-agent/report-v1",
                "repository": repo, "operation": "github.list_workflow_runs",
                "decision": "ALLOW", "status": "completed",
                "issuer_mode": "local-ephemeral-read-only",
                "checked": 0, "needs_attention": False, "failures": [],
                "in_progress": [], "evidence_root_hash": root, "audit_entries": 1,
            }, {"root_hash": root, "ledger_entries": [{"step": 1}]})
        with patch("shards_kernel.api.verify_evidence_bundle",
                   return_value=SimpleNamespace(is_valid=True)):
            result = run_read_job(self.db, job_id=next_job, inspector=valid)
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(refresh_task(self.db, next_task)["status"], "SUCCEEDED")
        self.assertEqual(refresh_task(self.db, self.task_id)["status"], "UNKNOWN")

    def test_reconciliation_requires_real_running_claim_and_valid_incident(self):
        with self.assertRaises(ValueError):
            reconcile_read_unknown(
                self.db, job_id=self.job_id, incident_id="x"
            )
        self.assertFalse(reconcile_read_unknown(
            self.db, job_id=self.job_id, incident_id="incident-20261104-003"
        ))
        from shards_agent_os.harness_cli import main
        self.assertEqual(
            main(["--db", self.db, "reconcile-read-unknown", self.job_id,
                  "--incident-id", "incident-20261104-003"]),
            2,
        )


if __name__ == "__main__":
    unittest.main()
