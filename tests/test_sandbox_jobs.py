"""Durable Agent OS sandbox job submission and fail-closed execution tests."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from shards_agent_os.interrupts import halt, resume
from shards_agent_os.sandbox_executor import ExecutionSpec
from shards_agent_os.sandbox_jobs import (
    SandboxJob, _summarise, enqueue_sandbox, run_sandbox_once,
    list_sandbox_jobs, cancel_sandbox_pending, reconcile_sandbox_unknown,
)
from shards_agent_os.scheduler import enqueue, run_once

IMAGE = "busybox@sha256:" + "a" * 64
OPERATOR_UID = os.geteuid() + 200


def params(**override):
    data = {
        "image": IMAGE,
        "argv": ["/bin/echo", "signed-sandbox-work"],
        "timeout_seconds": 20,
        "memory_megabytes": 256,
        "cpu_millicores": 500,
        "pids_limit": 32,
    }
    data.update(override)
    return data


def valid_result(arguments, *, status="EXITED", exit_code=0):
    digest = ExecutionSpec(
        image=arguments["image"], argv=tuple(arguments["argv"]),
        timeout_seconds=arguments["timeout_seconds"],
        memory_megabytes=arguments["memory_megabytes"],
        cpu_millicores=arguments["cpu_millicores"],
        pids_limit=arguments["pids_limit"],
    ).fingerprint()
    return {
        "decision": "ALLOW",
        "result": {
            "status": status, "exit_code": exit_code,
            "stdout": "signed-sandbox-work\n", "stderr": "", "duration_ms": 11,
            "fingerprint": digest, "cleanup_confirmed": True,
        },
    }


class SandboxQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "jobs.sqlite3"
        self.permit = str(Path(self.temp.name) / "permit.json")

    def queue(self, *, arguments=None, run_at=1, **options):
        return enqueue_sandbox(
            self.db, run_at_ms=run_at,
            arguments=params() if arguments is None else arguments,
            permit_file=self.permit, operator_uid=OPERATOR_UID,
            now_ms=0, **options,
        )

    def test_exactly_one_claim_and_durable_result(self):
        jid = self.queue()
        result = run_sandbox_once(self.db, now_ms=2, runner=lambda job, _: valid_result(job.arguments))
        self.assertEqual(result["job_id"], jid)
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(result["receipt"]["stdout"], "signed-sandbox-work\n")
        self.assertTrue(result["receipt"]["cleanup_confirmed"])
        self.assertIsNone(run_sandbox_once(self.db, now_ms=2, runner=lambda *_: self.fail("replayed")))
        self.assertEqual(list_sandbox_jobs(self.db)[0]["status"], "SUCCEEDED")
        self.assertNotIn(self.permit, json.dumps(list_sandbox_jobs(self.db)))
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)

    def test_denied_and_uncertain_never_retries(self):
        self.queue()
        denied = run_sandbox_once(self.db, now_ms=2, runner=lambda *_: {
            "decision": "DENY", "error": "Kernel denied operation",
        })
        self.assertEqual(denied["status"], "DENIED")
        self.queue()
        uncertain = run_sandbox_once(self.db, now_ms=2, runner=lambda *_: {
            "decision": "UNKNOWN", "error": "daemon restarted",
        })
        self.assertEqual(uncertain["status"], "UNKNOWN")
        self.assertIsNone(run_sandbox_once(self.db, now_ms=2))

    def test_tampered_fingerprint_or_unconfirmed_cleanup_are_unknown(self):
        for mutation in ("fingerprint", "cleanup_confirmed", "duration_ms", "exit_code"):
            with self.subTest(mutation=mutation):
                job_id = self.queue()
                def tamper(job, _):
                    reply = valid_result(job.arguments)
                    reply["result"][mutation] = {
                        "fingerprint": "f" * 64,
                        "cleanup_confirmed": False,
                        "duration_ms": True,
                        "exit_code": "0",
                    }[mutation]
                    return reply
                result = run_sandbox_once(self.db, now_ms=2, runner=tamper)
                self.assertEqual(result["job_id"], job_id)
                self.assertEqual(result["status"], "UNKNOWN")

    def test_cleanup_confirmed_failure_is_terminal(self):
        self.queue()
        result = run_sandbox_once(self.db, now_ms=2, runner=lambda job, _: valid_result(
            job.arguments, status="PROCESS_ERROR", exit_code=7,
        ))
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["receipt"]["exit_code"], 7)
        self.assertIsNone(run_sandbox_once(self.db, now_ms=2))

    def test_timeout_and_crashed_claim_do_not_retry(self):
        self.queue()
        result = run_sandbox_once(self.db, now_ms=2, runner=lambda *_: (_ for _ in ()).throw(
            TimeoutError("broker timed out"),
        ))
        self.assertEqual(result["status"], "UNKNOWN")
        self.queue()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE sandbox_jobs SET status='RUNNING' WHERE status='PENDING'")
        self.assertIsNone(run_sandbox_once(self.db, now_ms=2))
        jobs = list_sandbox_jobs(self.db)
        self.assertEqual(len([j for j in jobs if j["status"] == "RUNNING"]), 1)

    def test_halt_blocks_sandbox_claim_and_recovery_is_manual(self):
        jid = self.queue()
        halt(self.db, "maintenance")
        self.assertIsNone(run_sandbox_once(self.db, now_ms=2))
        self.assertEqual(list_sandbox_jobs(self.db)[0]["status"], "PENDING")
        resume(self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE sandbox_jobs SET status='RUNNING' WHERE job_id=?", (jid,))
        self.assertIsNone(run_sandbox_once(self.db, now_ms=2))
        self.assertTrue(reconcile_sandbox_unknown(self.db, job_id=jid, incident_id="INC-123"))
        self.assertFalse(reconcile_sandbox_unknown(self.db, job_id=jid, incident_id="INC-123"))
        self.assertEqual(list_sandbox_jobs(self.db)[0]["status"], "UNKNOWN")

    def test_cancel_pending_and_reject_invalid_args(self):
        jid = self.queue(run_at=100)
        self.assertTrue(cancel_sandbox_pending(self.db, jid))
        self.assertFalse(cancel_sandbox_pending(self.db, jid))
        self.assertIsNone(run_sandbox_once(self.db, now_ms=100))
        for bad in (params(image="busybox:latest"), params(pids_limit=True),
                    params(mount="/etc"), params(argv="unsafe")):
            with self.subTest(args=bad), self.assertRaises((ValueError, TypeError)):
                self.queue(arguments=bad)
        with self.assertRaises(ValueError):
            self.queue(socket_path="/tmp/spoofed-broker.sock")

    def test_shared_capacity_blocks_legacy_and_sandbox_in_both_directions(self):
        self.queue()
        started, release = threading.Event(), threading.Event()
        thread_result = []
        def hold(job, _):
            started.set()
            if not release.wait(8):
                raise TimeoutError("Test fixture lock")
            return valid_result(job.arguments)
        worker = threading.Thread(target=lambda: thread_result.append(
            run_sandbox_once(self.db, now_ms=2, runner=hold),
        ))
        worker.start()
        try:
            self.assertTrue(started.wait(5))
            enqueue(self.db, run_at_ms=1, port=1234, tool="echo",
                    arguments={"text": "test"}, permit_file=self.permit)
            self.assertIsNone(run_once(self.db, now_ms=2, runner=lambda *_: self.fail("legacy over-admitted")))
        finally:
            release.set()
            worker.join(timeout=8)
        self.assertFalse(worker.is_alive())
        self.assertEqual(thread_result[0]["status"], "SUCCEEDED")
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE jobs SET status='RUNNING' WHERE tool='echo'")
        self.queue()
        self.assertIsNone(run_sandbox_once(self.db, now_ms=2))

    def test_unprivileged_cli_enqueue_list_and_unknown_without_broker(self):
        source = Path(self.temp.name) / "args.json"
        source.write_text(json.dumps(params()))
        os.chmod(source, 0o600)
        command = [sys.executable, "-m", "shards_agent_os", "--db", str(self.db)]
        with patch.dict(os.environ, {"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}):
            def cli(*args):
                result = subprocess.run(command + list(args), capture_output=True,
                                        text=True, timeout=10)
                return result.returncode, json.loads(result.stdout)
            rc, submitted = cli(
                "sandbox-enqueue", "--operator-uid", str(OPERATOR_UID),
                "--arguments-file", str(source),
                "--permit-file", self.permit,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(submitted["status"], "PENDING")
            rc, listing = cli("sandbox-list")
            self.assertEqual(rc, 0)
            self.assertEqual(listing["jobs"][0]["job_id"], submitted["job_id"])
            self.assertNotIn(self.permit, json.dumps(listing))
            rc, status = cli("sandbox-run-once", "--timeout", "1")
            self.assertEqual(rc, 0)
            self.assertEqual(status["status"], "UNKNOWN")
            rc, status = cli("sandbox-run-once")
            self.assertEqual(status["status"], "NO_DUE_SANDBOX_JOB")


if __name__ == "__main__":
    unittest.main()
