"""Read-only recovery reporting over existing durable Agent OS state.

This module reconstructs what can be *proven* from the private SQLite state and
returns a bounded receipt for one job identifier. It never asserts that a
process is alive, never treats a recorded success as independent proof of an
external business effect, never retries and never mutates the database.

The report reuses the existing durable records: the signed MCP ``jobs`` queue,
the sandbox ``sandbox_jobs`` queue and the multi-step harness tables. It adds
no schema, no scheduler and no execution path.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from .harness import _JOB_TO_STEP, _READ_TOOL

_JOB_ID = re.compile(r"[0-9a-f]{32}")
_SCHEMA = "shards-agent-os/recovery-report-v1"

# A recorded durable state maps to a bounded completion verdict. It is never a
# claim about live process state or about external business effects.
_COMPLETION = {
    "SUCCEEDED": "VERIFIED",
    "RUNNING": "UNRESOLVED",
    "PENDING": "UNRESOLVED",
    "UNKNOWN": "UNKNOWN",
    "DENIED": "NOT_COMPLETED",
    "FAILED": "NOT_COMPLETED",
    "CANCELLED": "NOT_COMPLETED",
    "WAITING_PERMIT": "NOT_STARTED",
    "QUEUED": "NOT_STARTED",
    "PARTIAL": "PARTIAL",
}
# Only these two states require an operator reconciliation decision.
_RECONCILE = frozenset({"RUNNING", "UNKNOWN"})

_NEXT_ACTION = {
    "RUNNING": (
        "Operator: independently confirm the worker process is stopped and "
        "inspect the source of truth (kernel audit ledger, broker or container); "
        "then classify it with reconcile-unknown and an incident id. Do not replay."
    ),
    "UNKNOWN": (
        "Operator: inspect the recorded uncertainty and the source of truth. Do "
        "not retry. Enqueue a new, independently authorised job only if the work "
        "is still required."
    ),
    "PENDING": (
        "No execution has been claimed. Await dispatch or cancel the pending job; "
        "do not treat this as completion."
    ),
    "SUCCEEDED": (
        "None required for the recorded execution. Retain the evidence reference; "
        "external business effects are not independently verified."
    ),
    "DENIED": "None. Shards-Kernel denied the operation; this job applied no effect.",
    "FAILED": (
        "None automatic. The workload failed terminally; create a new authorised "
        "job if the work is still required."
    ),
    "CANCELLED": "None. The job was cancelled before it was claimed.",
    "WAITING_PERMIT": (
        "No step has been released. Obtain a fresh, independently issued permit "
        "only if the work is still required."
    ),
    "QUEUED": (
        "A step is queued for dispatch. Await the worker; do not treat this as "
        "completion."
    ),
    "PARTIAL": (
        "At least one step succeeded, but the task is not complete. Inspect the "
        "first unfinished stage and its existing job before seeking any new "
        "authorisation. Never replay a succeeded stage."
    ),
}

# Only these receipt fields are surfaced. Private execution arguments, permit
# paths, socket paths, operator identity and raw workload output are omitted.
_MCP_EVIDENCE_KEYS = ("decision", "request_id", "error", "incident_id")
_SANDBOX_EVIDENCE_KEYS = (
    "decision", "status", "exit_code", "duration_ms", "fingerprint",
    "cleanup_confirmed", "stdout_sha256", "stderr_sha256",
    "stdout_truncated", "stderr_truncated", "error", "incident_id",
)

# A stored receipt and its text fields are untrusted input: one corrupt or
# hostile row must not produce an unbounded receipt or a huge allocation.
_MAX_RECEIPT_BYTES = 262_144
_MAX_EVIDENCE_TEXT = 512

_BASE_UNRECOVERABLE = [
    "in-memory process state of the worker that attempted the job",
    "whether an external business effect completed, unless recorded below",
    "permit contents, signing material and private execution arguments "
    "(deliberately not stored or exposed)",
]


# A stored timestamp is untrusted input. datetime.fromtimestamp raises
# OverflowError or ValueError for values outside the platform range, so a
# corrupt row must degrade to an explicit unrepresentable marker rather than
# abort the whole receipt.
def _iso(ms: int) -> str | None:
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    except (OverflowError, ValueError, OSError):
        return None


def _timestamps(row: dict, keys: tuple[str, ...]) -> dict:
    recorded: dict = {}
    for key in keys:
        value = row.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            utc = _iso(value)
            recorded[key] = {"ms": value, "utc": utc} if utc else {
                "ms": value, "utc": None, "utc_representable": False,
            }
    return recorded


def _verdict(state: str) -> tuple[str, bool]:
    return _COMPLETION.get(state, "UNKNOWN"), state in _RECONCILE


def _read_only_connect(db_path: str | os.PathLike[str]) -> sqlite3.Connection:
    """Open the private state read-only, refusing symlinks and loose modes.

    The parent directory and file checks mirror ``storage.open_db`` so a report
    cannot be produced from a substituted or world-readable database.
    """
    path = Path(db_path)
    if not path.is_absolute() or not path.parent.is_dir():
        raise ValueError("Database requires an absolute path and existing parent directory")
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("Private SQLite state requires a POSIX host with O_NOFOLLOW")
    parent = os.stat(path.parent, follow_symlinks=False)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077):
        raise PermissionError("Database parent directory must be owned by this user and private (0700)")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o077)
                or info.st_uid != os.geteuid()):
            raise PermissionError("Database must be a regular file, owned by the process, mode 0600")
    finally:
        os.close(fd)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise PermissionError("Database path replaced during open")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA query_only=ON")
        return conn
    except BaseException:
        conn.close()
        raise


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}


def _bounded(value: object, limit: int = _MAX_EVIDENCE_TEXT) -> object:
    """Clamp a stored scalar so one corrupt row cannot inflate the receipt."""
    if isinstance(value, str):
        if len(value) <= limit:
            return value
        return value[:limit] + "…[truncated]"
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    return None


def _evidence(raw: str | None, allowed: tuple[str, ...]) -> dict:
    if not raw:
        return {"receipt": "none"}
    if not isinstance(raw, str) or len(raw) > _MAX_RECEIPT_BYTES:
        return {"receipt": "oversized"}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {"receipt": "unreadable"}
    if not isinstance(parsed, dict):
        return {"receipt": "unreadable"}
    evidence = {
        key: _bounded(parsed[key]) for key in allowed if key in parsed
    }
    if "result" in parsed:
        evidence["result_recorded"] = True
    return evidence or {"receipt": "none"}


def _base_report(row: dict, *, category: str, extra: dict | None = None) -> dict:
    state = row.get("status", "UNKNOWN")
    completion, reconcile = _verdict(state)
    report = {
        "execution_category": category,
        "durable_state": state,
        "completion": completion,
        "manual_reconciliation_required": reconcile,
        "smallest_safe_next_action": _NEXT_ACTION.get(
            state, "Operator: inspect the durable record before any action."
        ),
        "unrecoverable": list(_BASE_UNRECOVERABLE),
    }
    if extra:
        report.update(extra)
    return report


def _mcp_report(row: dict) -> dict:
    return _base_report(
        row, category="mcp_tool_job",
        extra={
            "tool": _bounded(row.get("tool"), 64),
            "recorded_timestamps": _timestamps(
                row, ("created_at_ms", "started_at_ms", "finished_at_ms", "run_at_ms")
            ),
            "evidence_reference": _evidence(row.get("result_json"), _MCP_EVIDENCE_KEYS),
        },
    )


def _sandbox_report(row: dict) -> dict:
    report = _base_report(
        row, category="sandbox_exec_job",
        extra={
            "recorded_timestamps": _timestamps(
                row, ("created_at_ms", "started_at_ms", "finished_at_ms", "run_at_ms")
            ),
            "evidence_reference": _evidence(row.get("result_json"), _SANDBOX_EVIDENCE_KEYS),
        },
    )
    report["unrecoverable"].append(
        "raw sandbox stdout/stderr (only SHA-256 digests and truncation flags are kept)"
    )
    return report


def _read_report(conn: sqlite3.Connection, row: dict, tables: set[str]) -> dict:
    incident_id = None
    if "harness_read_incidents" in tables:
        incident = conn.execute(
            "SELECT incident_id FROM harness_read_incidents WHERE job_id=?", (row["job_id"],)
        ).fetchone()
        incident_id = incident["incident_id"] if incident else None
    report = _base_report(
        row, category="harness_read_job",
        extra={
            "task_id": _bounded(row.get("task_id"), 64),
            "ordinal": row.get("ordinal"),
            "repository": _bounded(row.get("repository"), 201),
            "recorded_timestamps": _timestamps(
                row, ("created_at_ms", "started_at_ms", "finished_at_ms")
            ),
            "evidence_reference": {
                "evidence_root_hash": _bounded(row.get("root_hash"), 128),
                "report_recorded": row.get("report_json") is not None,
                "incident_id": incident_id,
            },
        },
    )
    report["unrecoverable"].append(
        "external GitHub state beyond the captured evidence bundle (no external anchor)"
    )
    return report


def _task_report(conn: sqlite3.Connection, row: dict, tables: set[str]) -> dict:
    """Reconcile cached harness state with child jobs without writing to either."""
    steps: list[dict] = []
    for s in conn.execute(
        "SELECT ordinal,tool,status,job_id FROM harness_steps "
        "WHERE task_id=? ORDER BY ordinal", (row["task_id"],)
    ):
        cached = s["status"]
        effective = cached
        if s["job_id"]:
            # Match harness._refresh_locked's exact tool-to-table association.
            # Missing, malformed or unrecognised child evidence fails closed.
            table = "harness_read_jobs" if s["tool"] == _READ_TOOL else "jobs"
            child = conn.execute(
                f"SELECT status FROM {table} WHERE job_id=?", (s["job_id"],)
            ).fetchone() if table in tables else None
            effective = _JOB_TO_STEP.get(child["status"], "UNKNOWN") if child else "UNKNOWN"
        steps.append({
            "ordinal": s["ordinal"], "tool": _bounded(s["tool"], 64),
            "status": effective, "recorded_step_state": cached,
            "job_id": s["job_id"],
        })

    states = [s["status"] for s in steps]
    # Unknown/running child operations take priority over apparent terminal
    # aggregate states. A previous success does not make an unfinished task safe.
    if not states or "UNKNOWN" in states:
        effective_state = "UNKNOWN"
    elif "RUNNING" in states:
        effective_state = "RUNNING"
    elif "DENIED" in states:
        effective_state = "DENIED"
    elif "CANCELLED" in states:
        effective_state = "CANCELLED"
    elif all(s == "SUCCEEDED" for s in states):
        effective_state = "SUCCEEDED"
    elif "SUCCEEDED" in states:
        effective_state = "PARTIAL"
    elif "QUEUED" in states:
        effective_state = "QUEUED"
    else:
        effective_state = "WAITING_PERMIT"

    progress = sum(s == "SUCCEEDED" for s in states)
    report = _base_report(
        {"status": effective_state},
        category="harness_task",
        extra={
            "name": _bounded(row.get("name"), 160),
            "recorded_task_state": row.get("status"),
            "recovery_state_derived_from_steps": True,
            "partial_progress": progress > 0 and progress < len(states),
            "step_progress": {"succeeded": progress, "total": len(states)},
            "recorded_timestamps": _timestamps(
                row, ("created_at_ms", "updated_at_ms")
            ),
            "steps": steps,
            "evidence_reference": {"steps_recorded": len(steps)},
        },
    )
    report["unrecoverable"].append(
        "per-step model reasoning; only the durable step states are recorded"
    )
    return report


def _matches(conn: sqlite3.Connection, job_id: str, tables: set[str]) -> list[dict]:
    found: list[dict] = []
    if "jobs" in tables:
        row = conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row:
            found.append(_mcp_report(dict(row)))
    if "sandbox_jobs" in tables:
        row = conn.execute("SELECT * FROM sandbox_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row:
            found.append(_sandbox_report(dict(row)))
    if "harness_read_jobs" in tables:
        row = conn.execute(
            "SELECT * FROM harness_read_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if row:
            found.append(_read_report(conn, dict(row), tables))
    if "harness_tasks" in tables:
        row = conn.execute(
            "SELECT * FROM harness_tasks WHERE task_id=?", (job_id,)
        ).fetchone()
        if row:
            found.append(_task_report(conn, dict(row), tables))
    return found


def build_recovery_report(
    db_path: str | os.PathLike[str], job_id: object, *, now_ms: int | None = None,
) -> dict:
    """Return a bounded, read-only recovery receipt for one durable job id.

    Absent or malformed identifiers produce an explicit ``NOT_FOUND`` result
    rather than an error. No execution, retry, reconciliation or state change
    is ever performed.
    """
    now = int(time.time() * 1000) if now_ms is None else now_ms
    base = {
        "schema": _SCHEMA,
        "generated_at_ms": now,
        "job_id": job_id if isinstance(job_id, str) else None,
        # A durable RUNNING record is not proof that a process is alive, and the
        # report never inspects the host to decide that.
        "live_process_observed": False,
        "durable_state_is_live_process_proof": False,
        "external_effects_verified": False,
    }
    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
        return {
            **base, "found": False, "durable_state": "NOT_FOUND",
            "execution_category": None, "completion": "UNKNOWN",
            "manual_reconciliation_required": False, "reason": "malformed_job_id",
            "smallest_safe_next_action": (
                "Supply a 32-character lowercase hexadecimal job id."
            ),
            "unrecoverable": ["the requested identifier is not a durable job id"],
        }
    path = Path(db_path)
    if not path.exists():
        return {
            **base, "found": False, "durable_state": "NOT_FOUND",
            "execution_category": None, "completion": "UNKNOWN",
            "manual_reconciliation_required": False, "reason": "database_absent",
            "smallest_safe_next_action": (
                "No durable state exists at this path; do not assume completion."
            ),
            "unrecoverable": ["no durable state was recorded"],
        }
    conn = _read_only_connect(db_path)
    try:
        matches = _matches(conn, job_id, _tables(conn))
    except sqlite3.DatabaseError:
        # A present but unreadable/corrupt file is a recovery finding, not a crash.
        return {
            **base, "found": False, "durable_state": "UNREADABLE",
            "execution_category": None, "completion": "UNKNOWN",
            "manual_reconciliation_required": True, "reason": "unreadable_database",
            "smallest_safe_next_action": (
                "The durable store could not be read. Preserve it, restore from a "
                "backup if available, and do not assume completion."
            ),
            "unrecoverable": ["the durable store could not be read"],
        }
    finally:
        conn.close()
    if not matches:
        return {
            **base, "found": False, "durable_state": "NOT_FOUND",
            "execution_category": None, "completion": "UNKNOWN",
            "manual_reconciliation_required": False, "reason": "no_durable_record",
            "smallest_safe_next_action": (
                "No durable record exists for this id; do not assume the task "
                "completed or that nothing happened."
            ),
            "unrecoverable": ["no durable record was found for this id"],
        }
    primary = matches[0]
    report = {**base, **primary, "found": True}
    report["also_present_in"] = [m["execution_category"] for m in matches[1:]]
    return report
