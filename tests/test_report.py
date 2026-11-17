"""Operational report export: read-only, offline, allowlisted and escaped."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shards_agent_os.interrupts import halt
from shards_agent_os.recurrence import create_schedule
from shards_agent_os.report import (
    ReportError, collect_snapshot, export_report, render_report,
)
from shards_agent_os.sandbox_jobs import enqueue_sandbox
from shards_agent_os.scheduler import enqueue, run_once
from shards_agent_os.storage import open_db

RECEIPT = "mcp-relay-" + "e" * 32
IMAGE = "busybox@sha256:" + "a" * 64
OPERATOR_UID = os.geteuid() + 200

_TABLES = ("jobs", "sandbox_jobs", "control", "recurring_schedules", "memory")


def sandbox_arguments(**override):
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


def _logical_state(db: Path) -> dict:
    """Full logical row dump, used to prove the export mutates nothing."""
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    try:
        conn.row_factory = sqlite3.Row
        dump = {}
        for table in _TABLES:
            rows = [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]
            dump[table] = rows
        return dump
    finally:
        conn.close()


class ReportExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.db = self.dir / "jobs.sqlite"
        self.output = self.dir / "report.html"
        self.permit = str(self.dir / "permit.json")

    # -- helpers ------------------------------------------------------------
    def _seed_running_job(self) -> str:
        """Insert a stuck RUNNING job directly, mirroring a crashed worker."""
        with open_db(self.db) as conn:
            conn.execute(
                "INSERT INTO jobs (job_id,run_at_ms,port,tool,arguments_json,"
                "permit_file,status,created_at_ms,started_at_ms) "
                "VALUES (?,?,?,?,?,?,'RUNNING',?,?)",
                ("f" * 32, 1, 8765, "echo", '{"text":"x"}', self.permit, 1, 2),
            )
        return "f" * 32

    def _export(self, **kwargs) -> str:
        export_report(self.db, self.output, now_ms=1_700_000_000_000, **kwargs)
        return self.output.read_text(encoding="utf-8")

    # -- behaviour ----------------------------------------------------------
    def test_snapshot_summarises_jobs_sandbox_schedules_and_halt(self):
        enqueue(self.db, run_at_ms=0, port=8765, tool="echo",
                arguments={"text": "ping"}, permit_file=self.permit)
        run_once(self.db, now_ms=10,
                 runner=lambda job, _: (0, json.dumps(
                     {"decision": "ALLOW", "request_id": RECEIPT, "result": "ping"})))
        enqueue_sandbox(self.db, run_at_ms=0, arguments=sandbox_arguments(),
                        permit_file=self.permit, operator_uid=OPERATOR_UID, now_ms=0)
        create_schedule(self.db, name="heartbeat", interval_ms=60_000,
                        start_at_ms=1000, window_ms=5000, port=8765,
                        tool="echo", arguments={"text": "ping"})
        halt(self.db, reason="operator maintenance")

        snap = collect_snapshot(self.db, now_ms=1_700_000_000_000)
        self.assertTrue(snap["control"]["halted"])
        self.assertEqual(snap["control"]["reason"], "operator maintenance")
        self.assertEqual(snap["job_counts"]["SUCCEEDED"], 1)
        self.assertEqual(snap["job_counts"]["PENDING"], 0)
        self.assertEqual(snap["sandbox_counts"]["PENDING"], 1)
        self.assertEqual(len(snap["schedules"]), 1)

        html = render_report(snap)
        self.assertIn("MCP job summary", html)
        self.assertIn("Sandbox job summary", html)
        self.assertIn("Scheduling", html)
        self.assertIn("HALTED", html)
        self.assertIn("heartbeat", html)

    def test_outstanding_unknown_and_running_are_flagged(self):
        self._seed_running_job()
        with open_db(self.db) as conn:
            conn.execute(
                "INSERT INTO sandbox_jobs (job_id,run_at_ms,socket_path,operator_uid,"
                "arguments_json,permit_file,status,created_at_ms,started_at_ms) "
                "VALUES (?,?,?,?,?,?,'UNKNOWN',?,?)",
                ("c" * 32, 1, "/run/shards-sandbox/broker.sock", OPERATOR_UID,
                 "{}", self.permit, 1, 2),
            )
        html = self._export()
        self.assertIn("Outstanding jobs", html)
        self.assertIn("reconciliation", html)
        self.assertIn("f" * 32, html)
        self.assertIn("c" * 32, html)

    def test_export_is_read_only_and_never_executes_or_enqueues(self):
        self._seed_running_job()
        enqueue_sandbox(self.db, run_at_ms=0, arguments=sandbox_arguments(),
                        permit_file=self.permit, operator_uid=OPERATOR_UID, now_ms=0)
        before = _logical_state(self.db)

        with patch("shards_agent_os.scheduler.run_once",
                   side_effect=AssertionError("report must not execute MCP jobs")), \
                patch("shards_agent_os.daemon.serve",
                      side_effect=AssertionError("report must not run the worker")), \
                patch("shards_agent_os.sandbox_jobs.run_sandbox_once",
                      side_effect=AssertionError("report must not execute sandbox jobs")), \
                patch("shards_agent_os.sandbox_jobs.serve_sandbox",
                      side_effect=AssertionError("report must not serve sandbox jobs")):
            self._export()

        after = _logical_state(self.db)
        self.assertEqual(before, after, "export changed runtime state")
        # The stuck RUNNING job is deliberately left untouched (no auto-retry).
        statuses = {row["status"] for row in after["jobs"]}
        self.assertEqual(statuses, {"RUNNING"})

    def test_empty_state_renders_useful_placeholders(self):
        with open_db(self.db):
            pass  # create schema only, no rows
        html = self._export()
        self.assertIn("No jobs recorded.", html)
        self.assertIn("No recurring schedule templates recorded.", html)
        self.assertIn("Nothing requires reconciliation.", html)
        self.assertIn("ACTIVE", html)

    def test_malicious_display_values_are_escaped(self):
        payload_reason = "<script>alert('halt')</script>"
        halt(self.db, reason=payload_reason)
        with open_db(self.db) as conn:
            conn.execute(
                "INSERT INTO recurring_schedules (schedule_id,name,interval_ms,"
                "next_due_ms,window_ms,port,tool,arguments_json,enabled) "
                "VALUES (?,?,?,?,?,?,?,?,1)",
                ("b" * 32, '<img src=x onerror=alert(1)>', 60_000, 1000, 5000,
                 8765, "echo", "{}"),
            )
            conn.execute(
                "INSERT INTO sandbox_jobs (job_id,run_at_ms,socket_path,operator_uid,"
                "arguments_json,permit_file,status,result_json,created_at_ms) "
                "VALUES (?,?,?,?,?,?,'UNKNOWN',?,?)",
                ("d" * 32, 1, "/run/shards-sandbox/broker.sock", OPERATOR_UID,
                 "{}", self.permit, json.dumps({"error": "<script>boom()</script>"}), 1),
            )
        html = self._export()
        # Payloads appear only as inert entity-escaped text.
        self.assertNotIn(payload_reason, html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<script>boom", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_permits_arguments_and_output_are_never_exported(self):
        enqueue(self.db, run_at_ms=0, port=8765, tool="echo",
                arguments={"text": "SUPER_SECRET_TEXT"}, permit_file="/secret/permits/one-use.json")
        run_once(self.db, now_ms=10, runner=lambda job, _: (0, json.dumps(
            {"decision": "ALLOW", "request_id": RECEIPT, "result": "SUPER_SECRET_TEXT"})))
        enqueue_sandbox(self.db, run_at_ms=0,
                        arguments=sandbox_arguments(argv=["/bin/echo", "TOPSECRET_ARGV"]),
                        permit_file="/secret/permits/sandbox.json",
                        operator_uid=OPERATOR_UID, now_ms=0)
        with open_db(self.db) as conn:
            conn.execute("UPDATE sandbox_jobs SET result_json=? WHERE status='PENDING'",
                         (json.dumps({"decision": "ALLOW", "exit_code": 0,
                                      "duration_ms": 5, "stdout": "LEAKED_STDOUT",
                                      "fingerprint": "a" * 64}),))
        html = self._export()
        for secret in ("SUPER_SECRET_TEXT", "/secret/permits", "one-use.json",
                       "sandbox.json", "TOPSECRET_ARGV", "LEAKED_STDOUT", IMAGE,
                       "fingerprint", "permit_file", "arguments_json"):
            self.assertNotIn(secret, html, f"leaked {secret!r} into report")

    def test_self_contained_and_offline(self):
        enqueue(self.db, run_at_ms=0, port=8765, tool="echo",
                arguments={"text": "ping"}, permit_file=self.permit)
        html = self._export()
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn('name="viewport"', html)
        self.assertIn("prefers-color-scheme", html)
        self.assertIn('data-theme="dark"', html)  # manual light/dark override
        self.assertIn("point-in-time", html.lower())
        for forbidden in ("http://", "https://", "//cdn", "<link", "<script src",
                          "src=\"http", "integrity="):
            self.assertNotIn(forbidden, html, f"external reference {forbidden!r} present")

    def test_output_is_private_regular_file(self):
        with open_db(self.db):
            pass
        export_report(self.db, self.output, now_ms=1)
        self.assertTrue(self.output.is_file())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_refuses_symlink_output(self):
        with open_db(self.db):
            pass
        real = self.dir / "elsewhere.html"
        real.write_text("keep", encoding="utf-8")
        link = self.dir / "link.html"
        link.symlink_to(real)
        with self.assertRaises(OSError):
            export_report(self.db, link, now_ms=1)
        self.assertEqual(real.read_text(encoding="utf-8"), "keep")

    def test_missing_database_is_rejected(self):
        with self.assertRaises(ReportError):
            export_report(self.dir / "absent.sqlite", self.output, now_ms=1)

    def test_missing_output_parent_is_rejected(self):
        with open_db(self.db):
            pass
        with self.assertRaises(ReportError):
            export_report(self.db, self.dir / "no_such_dir" / "r.html", now_ms=1)

    # -- output safety (P0) -------------------------------------------------
    def test_refuses_existing_output_by_default(self):
        with open_db(self.db):
            pass
        self.output.write_text("PRECIOUS", encoding="utf-8")
        with self.assertRaises(OSError):
            export_report(self.db, self.output, now_ms=1)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "PRECIOUS")

    def test_refuses_output_that_is_the_database_path(self):
        with open_db(self.db):
            pass
        before = self.db.read_bytes()
        with self.assertRaises(OSError):
            export_report(self.db, self.db, now_ms=1)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(_logical_state(self.db)["control"][0]["halted"], 0)

    def test_refuses_hard_link_to_database_by_default(self):
        self._seed_running_job()
        before = self.db.read_bytes()
        os.link(self.db, self.output)  # a second name for the very same inode
        with self.assertRaises(OSError):
            export_report(self.db, self.output, now_ms=1)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.output.stat().st_ino, self.db.stat().st_ino)

    def test_overwrite_refuses_hard_link_to_database(self):
        self._seed_running_job()
        before = _logical_state(self.db)
        os.link(self.db, self.output)
        with self.assertRaises(ReportError):
            export_report(self.db, self.output, now_ms=1, overwrite=True)
        self.assertEqual(_logical_state(self.db), before)

    def test_overwrite_refuses_database_path(self):
        with open_db(self.db):
            pass
        before = self.db.read_bytes()
        with self.assertRaises(ReportError):
            export_report(self.db, self.db, now_ms=1, overwrite=True)
        self.assertEqual(self.db.read_bytes(), before)

    def test_overwrite_replaces_existing_report(self):
        with open_db(self.db):
            pass
        self.output.write_text("OLD", encoding="utf-8")
        result = export_report(self.db, self.output, now_ms=1, overwrite=True)
        self.assertEqual(result["status"], "EXPORTED")
        self.assertTrue(result["overwritten"])
        self.assertIn("Shards Agent OS", self.output.read_text(encoding="utf-8"))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    # -- fail-closed reads (P2) --------------------------------------------
    def test_absent_optional_tables_render_as_empty(self):
        with open_db(self.db) as conn:
            conn.execute("DROP TABLE jobs")
            conn.execute("DROP TABLE sandbox_jobs")
            conn.execute("DROP TABLE recurring_schedules")
        snap = collect_snapshot(self.db, now_ms=1)
        self.assertEqual(snap["jobs"], [])
        self.assertEqual(snap["sandbox_jobs"], [])
        self.assertEqual(snap["schedules"], [])

    def test_missing_control_table_is_an_error_not_empty(self):
        empty = self.dir / "empty.sqlite"
        empty.write_bytes(b"")
        os.chmod(empty, 0o600)
        with self.assertRaises(ReportError):
            collect_snapshot(empty, now_ms=1)

    def test_corrupt_database_is_an_error_not_empty(self):
        corrupt = self.dir / "corrupt.sqlite"
        corrupt.write_bytes(b"this is definitely not a sqlite database" * 4)
        os.chmod(corrupt, 0o600)
        with self.assertRaises(ReportError):
            collect_snapshot(corrupt, now_ms=1)

    # -- sandbox diagnostic redaction (P3) ----------------------------------
    def _seed_sandbox_result(self, result: dict, *, status: str = "FAILED") -> None:
        with open_db(self.db) as conn:
            conn.execute(
                "INSERT INTO sandbox_jobs (job_id,run_at_ms,socket_path,operator_uid,"
                "arguments_json,permit_file,status,result_json,created_at_ms) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                ("e" * 32, 1, "/run/shards-sandbox/broker.sock", OPERATOR_UID,
                 json.dumps(sandbox_arguments()), self.permit, status,
                 json.dumps(result), 1),
            )

    def test_sandbox_error_text_is_reduced_to_allowlisted_category(self):
        secret_path = "/home/operator/.ssh/id_ed25519"
        secret_token = "TOPSECRET_TOKEN_ABC123"
        secret_arg = "SUPER_SECRET_ARGV"
        error = (f"permission denied reading {secret_path} "
                 f"token={secret_token} argv={secret_arg}")
        self._seed_sandbox_result(
            {"decision": "ALLOW", "exit_code": 126, "error": error},
        )
        html = self._export()
        for secret in (secret_path, secret_token, secret_arg, error):
            self.assertNotIn(secret, html, f"leaked {secret!r} into report")
        self.assertIn("PERMISSION_DENIED", html)
        self.assertIn("Diagnostic", html)

    def test_sandbox_unmatched_error_becomes_unclassified(self):
        unknown = "kernel oops at 0xdeadbeef while mapping pages"
        self._seed_sandbox_result({"decision": "ALLOW", "error": unknown})
        html = self._export()
        self.assertNotIn("0xdeadbeef", html)
        self.assertNotIn(unknown, html)
        self.assertIn("UNCLASSIFIED", html)

    # -- theme control ------------------------------------------------------
    def test_theme_toggle_is_wired_after_dom_is_parsed(self):
        with open_db(self.db):
            pass
        html = self._export()
        button_at = html.index('id="theme-toggle"')
        toggle_at = html.index("DOMContentLoaded")
        restore_at = html.index("localStorage.getItem")
        # The saved theme is applied before the button renders (no flash)...
        self.assertLess(restore_at, button_at)
        # ...and the click handler is only wired once the DOM is available.
        self.assertLess(button_at, toggle_at)
        self.assertIn("addEventListener('click'", html)


class ReportCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.db = self.dir / "jobs.sqlite"
        self.output = self.dir / "report.html"

    def _run(self, *extra):
        return subprocess.run(
            [sys.executable, "-m", "shards_agent_os", "--db", str(self.db),
             "export-report", "--output", str(self.output), *extra],
            capture_output=True, text=True, check=False,
        )

    def test_cli_exports_report_and_reports_json(self):
        enqueue(self.db, run_at_ms=0, port=8765, tool="echo",
                arguments={"text": "ping"}, permit_file=str(self.dir / "permit.json"))
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "EXPORTED")
        self.assertTrue(self.output.is_file())
        self.assertIn("Shards Agent OS", self.output.read_text(encoding="utf-8"))

    def test_cli_rejects_invalid_input_with_exit_code_two(self):
        completed = self._run("--nonsense")
        self.assertEqual(completed.returncode, 2)

    def test_cli_reports_missing_database_as_error(self):
        completed = self._run()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")

    def test_cli_refuses_existing_output_without_touching_it(self):
        with open_db(self.db):
            pass
        self.output.write_text("KEEP", encoding="utf-8")
        completed = self._run()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")
        self.assertEqual(self.output.read_text(encoding="utf-8"), "KEEP")
        self.assertNotIn("Traceback", completed.stderr)

    def test_cli_refuses_hard_link_to_database(self):
        with open_db(self.db):
            pass
        before = self.db.read_bytes()
        os.link(self.db, self.output)
        completed = self._run()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")
        self.assertEqual(self.db.read_bytes(), before)

    def test_cli_corrupt_database_is_clean_error_not_traceback(self):
        self.db.write_bytes(b"not a database" * 8)
        os.chmod(self.db, 0o600)
        completed = self._run()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")
        self.assertNotIn("Traceback", completed.stderr)

    def test_help_lists_export_report(self):
        completed = subprocess.run(
            [sys.executable, "-m", "shards_agent_os", "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertIn("export-report", completed.stdout)


if __name__ == "__main__":
    unittest.main()
