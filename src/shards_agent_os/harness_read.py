"""Durable read-only GitHub observation adapter for the Shards Agent Harness.

A *trusted local provider* supplies the existing kernel-governed GitHub inspector.
This module does not possess a GitHub token, mint permits, or execute writes.
The observation job is intentionally separate from the signed-v2 echo/add queue.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Callable

from .harness import _READ_TOOL, _TERMINAL, _connect, _now_ms, _refresh_locked

_SHA256 = re.compile(r"[0-9a-f]{64}")
_JOB_ID = re.compile(r"[0-9a-f]{32}")


def release_read_step(db_path: str, *, task_id: str, ordinal: int) -> str:
    """Atomically queue the explicitly supported read-only observer.

    Local operator approval is NOT a signed Shards-Kernel permit. The trusted
    GitHub monitor applies its existing separate read-only kernel decision.
    """
    if type(ordinal) is not int or ordinal < 0:
        raise ValueError("Invalid ordinal")
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = _refresh_locked(conn, task_id)
        if current in _TERMINAL:
            raise ValueError("Task already terminal")
        control = conn.execute("SELECT halted FROM control WHERE singleton=1").fetchone()
        if not control or control["halted"]:
            raise ValueError("Dispatch halted")
        stages = conn.execute(
            "SELECT ordinal,tool,status,job_id,arguments_json FROM harness_steps "
            "WHERE task_id=? ORDER BY ordinal", (task_id,),
        ).fetchall()
        if ordinal >= len(stages) or stages[ordinal]["ordinal"] != ordinal:
            raise ValueError("Unknown stage")
        if any(stage["status"] != "SUCCEEDED" for stage in stages[:ordinal]):
            raise ValueError("Preceding stage has not succeeded")
        stage = stages[ordinal]
        if stage["tool"] != _READ_TOOL or stage["status"] != "WAITING_PERMIT" or stage["job_id"]:
            raise ValueError("Not an eligible read-only stage")
        repository = json.loads(stage["arguments_json"])["repository"]
        job_id, now = uuid.uuid4().hex, _now_ms()
        conn.execute(
            "INSERT INTO harness_read_jobs "
            "(job_id,task_id,ordinal,repository,status,created_at_ms) VALUES (?,?,?,?,?,?)",
            (job_id,task_id,ordinal,repository,"PENDING",now),
        )
        conn.execute(
            "UPDATE harness_steps SET status='QUEUED',job_id=? WHERE task_id=? AND ordinal=?",
            (job_id,task_id,ordinal),
        )
        conn.execute(
            "UPDATE harness_tasks SET status='QUEUED',updated_at_ms=? WHERE task_id=?",
            (now,task_id),
        )
        return job_id


def _check_report(repository: str, report: dict, evidence: dict) -> str:
    """Verify internal consistency and the supported read-only report contract."""
    if type(report) is not dict or type(evidence) is not dict:
        raise ValueError("Report and evidence must be objects")
    if (report.get("schema") != "shards-github-agent/report-v1"
            or report.get("operation") != _READ_TOOL
            or report.get("repository") != repository
            or report.get("decision") != "ALLOW"
            or report.get("status") != "completed"
            or report.get("issuer_mode") != "local-ephemeral-read-only"):
        raise ValueError("Unsupported GitHub inspection receipt")
    root = report.get("evidence_root_hash")
    if type(root) is not str or not _SHA256.fullmatch(root):
        raise ValueError("Invalid evidence root")
    if root != evidence.get("root_hash"):
        raise ValueError("Evidence root mismatch")
    entries = evidence.get("ledger_entries")
    if (type(entries) is not list or not entries
            or type(report.get("audit_entries")) is not int
            or report["audit_entries"] != len(entries)):
        raise ValueError("Missing or inconsistent audit entries")
    if (type(report.get("checked")) is not int
            or not 0 <= report["checked"] <= 10
            or type(report.get("needs_attention")) is not bool
            or type(report.get("failures")) is not list
            or type(report.get("in_progress")) is not list):
        raise ValueError("Malformed inspection summary")
    # The source agent already independently checks the same bundle; this
    # recheck catches accidental corruption at the harness integration seam.
    from shards_kernel.api import verify_evidence_bundle

    if not verify_evidence_bundle(evidence).is_valid:
        raise ValueError("Kernel evidence replay invalid")
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("Inspection report too large")
    bundle_json = json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(bundle_json.encode("utf-8")) > 524288:
        raise ValueError("Inspection evidence too large")
    return encoded, bundle_json


def run_read_job(
    db_path: str, *, job_id: str, inspector: Callable[[str], tuple[dict, dict]]
) -> dict:
    """Claim one read-only observation, invoke its trusted inspector and checkpoint.

    RUNNING after a crash is deliberately not reissued, even though GET is
    normally replay-safe. A human can create a new task after reconciliation.
    """
    if type(job_id) is not str or not _JOB_ID.fullmatch(job_id):
        raise ValueError("Invalid observation job ID")
    if not callable(inspector):
        raise ValueError("A trusted read-only inspector is required")
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT job_id,task_id,ordinal,repository,status FROM harness_read_jobs "
            "WHERE job_id=?", (job_id,),
        ).fetchone()
        if not row or row["status"] != "PENDING":
            raise ValueError("Job unavailable or previously attempted")
        halted = conn.execute("SELECT halted FROM control WHERE singleton=1").fetchone()
        if not halted or halted["halted"]:
            raise ValueError("Dispatch halted")
        busy = conn.execute(
            "SELECT (SELECT COUNT(*) FROM jobs WHERE status='RUNNING') + "
            "(SELECT COUNT(*) FROM harness_read_jobs WHERE status='RUNNING')"
        ).fetchone()[0]
        if busy:
            raise ValueError("A local job is already running")
        conn.execute(
            "UPDATE harness_read_jobs SET status='RUNNING',started_at_ms=? WHERE job_id=? "
            "AND status='PENDING'", (_now_ms(),job_id),
        )
        conn.execute(
            "UPDATE harness_steps SET status='RUNNING' WHERE task_id=? AND ordinal=?",
            (row["task_id"],row["ordinal"]),
        )
        conn.execute(
            "UPDATE harness_tasks SET status='RUNNING',updated_at_ms=? WHERE task_id=?",
            (_now_ms(),row["task_id"]),
        )
        repository, task_id = row["repository"], row["task_id"]

    # Never retain GitHub tokens, permit material, exception text or arbitrary
    # model output in SQLite. The inspector is trusted local Python code.
    report, evidence = None, None
    try:
        candidate_report, candidate_evidence = inspector(repository)
        encoded, encoded_evidence = _check_report(
            repository, candidate_report, candidate_evidence
        )
        report, evidence = candidate_report, candidate_evidence
        status = "SUCCEEDED"
    except Exception:
        encoded, encoded_evidence, status = None, None, "UNKNOWN"
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if status == "SUCCEEDED":
            # Evidence and the terminal success state must commit atomically.
            # A crash cannot leave a successful observation without its proof.
            conn.execute(
                "INSERT INTO harness_read_evidence (job_id,evidence_json) VALUES (?,?)",
                (job_id, encoded_evidence),
            )
        changed = conn.execute(
            "UPDATE harness_read_jobs SET status=?,report_json=?,root_hash=?,finished_at_ms=? "
            "WHERE job_id=? AND status='RUNNING'",
            (status,encoded,report["evidence_root_hash"] if report else None,_now_ms(),job_id),
        )
        if changed.rowcount != 1:
            raise RuntimeError("Claim changed while inspection was executing")
        _refresh_locked(conn, task_id)
    return {"job_id":job_id,"task_id":task_id,"status":status,
            "report":report if status == "SUCCEEDED" else None,
            "evidence":evidence if status == "SUCCEEDED" else None}


def get_read_job(db_path: str, job_id: str) -> dict:
    """Return the redacted persisted state without reissuing a network call."""
    if type(job_id) is not str or not _JOB_ID.fullmatch(job_id):
        raise ValueError("Invalid job ID")
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT job_id,task_id,ordinal,repository,status,report_json,root_hash,"
            "created_at_ms,started_at_ms,finished_at_ms FROM harness_read_jobs WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if not row:
            raise ValueError("Unknown observation job")
        result = dict(row)
        result["report"] = json.loads(result.pop("report_json")) if row["report_json"] else None
        return result


def get_read_evidence(db_path: str, job_id: str) -> dict:
    """Replay-verify a persisted success result without executing a tool.

    Suitable for rebuilding output files after a process dies after the SQLite
    commit. The evidence is stored in the same private 0600 database. An
    external immutable anchor is still needed for independent attestation.
    """
    if type(job_id) is not str or not _JOB_ID.fullmatch(job_id):
        raise ValueError("Invalid observation job ID")
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT r.repository,r.status,r.report_json,r.root_hash,e.evidence_json "
            "FROM harness_read_jobs AS r "
            "LEFT JOIN harness_read_evidence AS e ON e.job_id=r.job_id "
            "WHERE r.job_id=?", (job_id,),
        ).fetchone()
        if row is None or row["status"] != "SUCCEEDED":
            raise ValueError("Observation is not successful")
        if row["report_json"] is None or row["evidence_json"] is None:
            raise ValueError("Successful observation is missing evidence")
        try:
            report = json.loads(row["report_json"])
            evidence = json.loads(row["evidence_json"])
            _check_report(row["repository"], report, evidence)
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("Persisted evidence failed verification") from exc
        if row["root_hash"] != report["evidence_root_hash"]:
            raise ValueError("Persisted evidence root mismatch")
        return {"report": report, "evidence": evidence}
