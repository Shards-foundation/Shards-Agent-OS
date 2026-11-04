"""Interval schedule templates: no authority, no automatic permit issuance.

Each occurrence requires a fresh externally signed one-use permit, supplied
only when the operator explicitly releases that occurrence into the job queue.

This module never reads permit contents, signs permits, calls an API, or
executes a tool. Kernel enforcement remains separate and mandatory.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

from .scheduler import _validate_job
from .storage import open_db

MAX_TIME_MS = 253402300799000  # a bounded year-9999 UTC epoch millisecond
MIN_INTERVAL_MS = 60_000
MAX_INTERVAL_MS = 31 * 24 * 60 * 60 * 1000
MAX_WINDOW_MS = 24 * 60 * 60 * 1000
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def _clock(now_ms: int | None) -> int:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if type(now) is not int or not 0 <= now <= MAX_TIME_MS:
        raise ValueError("Invalid bounded Unix epoch milliseconds")
    return now


def _advance_clock(conn, now: int) -> None:
    prior = conn.execute(
        "SELECT high_water_ms FROM schedule_clock WHERE singleton=1"
    ).fetchone()[0]
    if now < prior:
        raise ValueError("SCHEDULE_CLOCK_ROLLBACK")
    conn.execute(
        "UPDATE schedule_clock SET high_water_ms=? WHERE singleton=1", (now,)
    )


def create_schedule(
    db_path: str | Path, *, name: str, interval_ms: int, start_at_ms: int,
    window_ms: int, port: int, tool: str, arguments: dict,
) -> str:
    """Create an inert recurring intent; cannot execute without a new permit."""
    if type(name) is not str or not _NAME.fullmatch(name):
        raise ValueError("Schedule name must be 1..64 safe characters")
    if type(interval_ms) is not int or not MIN_INTERVAL_MS <= interval_ms <= MAX_INTERVAL_MS:
        raise ValueError("Interval must be between one minute and 31 days")
    if type(start_at_ms) is not int or not 0 <= start_at_ms <= MAX_TIME_MS:
        raise ValueError("Invalid start time")
    if type(window_ms) is not int or not 1000 <= window_ms <= min(MAX_WINDOW_MS, interval_ms):
        raise ValueError("Window must be 1 second..24 hours and <= interval")
    # This validation covers the restricted tool/parameters/port. A permit
    # path is not applicable to an inert template; execution needs a real one.
    _validate_job(tool, arguments, port, "/not-issued/schedule-template-only")
    schedule_id = uuid.uuid4().hex
    with open_db(db_path) as conn:
        conn.execute("""INSERT INTO recurring_schedules
            (schedule_id,name,interval_ms,next_due_ms,window_ms,port,tool,
             arguments_json,enabled) VALUES (?,?,?,?,?,?,?,?,1)""",
             (schedule_id, name, interval_ms, start_at_ms, window_ms, port, tool,
              json.dumps(arguments, sort_keys=True, separators=(",", ":"), allow_nan=False)))
    return schedule_id


def list_schedules(db_path: str | Path) -> list[dict]:
    """List only nonsecret template metadata; never expose permit paths."""
    with open_db(db_path) as conn:
        rows = conn.execute("""SELECT schedule_id,name,interval_ms,next_due_ms,
                window_ms,tool,enabled,last_job_id,skipped_intervals
                FROM recurring_schedules ORDER BY name""").fetchall()
        return [dict(row) for row in rows]


def set_schedule_enabled(db_path: str | Path, schedule_id: str, enabled: bool) -> bool:
    if type(enabled) is not bool or type(schedule_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", schedule_id):
        raise ValueError("Invalid schedule state or ID")
    with open_db(db_path) as conn:
        return conn.execute(
            "UPDATE recurring_schedules SET enabled=? WHERE schedule_id=? AND enabled!=?",
            (int(enabled), schedule_id, int(enabled))
        ).rowcount == 1


def due_schedules(db_path: str | Path, *, now_ms: int | None = None) -> list[dict]:
    """Observe candidate schedules, without issuing jobs or authorisation."""
    now = _clock(now_ms)
    with open_db(db_path) as conn:
        rows = conn.execute("""SELECT schedule_id,name,interval_ms,next_due_ms,
                window_ms,tool FROM recurring_schedules
                WHERE enabled=1 AND next_due_ms <= ? ORDER BY next_due_ms, name""",
                (now,)).fetchall()
        return [dict(row) for row in rows]


def release_occurrence(
    db_path: str | Path, *, schedule_id: str, permit_file: str,
    now_ms: int | None = None,
) -> dict:
    """Release at most one timely occurrence with an independently issued permit.

    The transaction atomically updates the next due time and inserts a job.
    A missed window skips all expired intervals without creating any job.
    No automatic retry, no permit reissue, and no execution occurs here.
    """
    now = _clock(now_ms)
    if type(schedule_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", schedule_id):
        raise ValueError("Invalid schedule ID")
    if (type(permit_file) is not str or not Path(permit_file).is_absolute()
            or not 1 <= len(permit_file) <= 4096):
        raise ValueError("Absolute externally issued permit path required")
    with open_db(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        _advance_clock(conn, now)
        control = conn.execute("SELECT halted FROM control WHERE singleton=1").fetchone()
        if control["halted"]:
            raise ValueError("DISPATCH_HALTED")
        row = conn.execute(
            "SELECT * FROM recurring_schedules WHERE schedule_id=?", (schedule_id,)
        ).fetchone()
        if row is None or not row["enabled"]:
            raise ValueError("SCHEDULE_NOT_AVAILABLE")
        due = row["next_due_ms"]
        if now < due:
            return {"status": "NOT_DUE", "schedule_id": schedule_id, "next_due_ms": due}
        interval = row["interval_ms"]
        elapsed = (now - due) // interval
        # First due strictly after 'now', retaining original recurrence phase.
        next_due = due + (elapsed + 1) * interval
        if next_due > MAX_TIME_MS:
            raise ValueError("SCHEDULE_TIME_OVERFLOW")
        if elapsed > 0 or now - due > row["window_ms"]:
            skipped = elapsed + 1 if now - (due + elapsed * interval) > row["window_ms"] else elapsed
            # If the current interval remains within its window, it is
            # eligible; earlier periods are discarded without backlog.
            if now - (due + elapsed * interval) > row["window_ms"]:
                conn.execute("""UPDATE recurring_schedules SET next_due_ms=?,
                    skipped_intervals=skipped_intervals+? WHERE schedule_id=?""",
                    (next_due, skipped, schedule_id))
                return {"status": "MISSED", "schedule_id": schedule_id,
                        "skipped": skipped, "next_due_ms": next_due}
            # Current period is still within the issue window: skip prior
            # windows, release exactly one fresh occurrence.
        else:
            skipped = 0
        # A reused permit-file path is a preventable operator mistake. This
        # does NOT prove the permit contents are unique; the kernel verifies
        # its cryptographic nonce and execution constraints independently.
        if conn.execute("SELECT 1 FROM jobs WHERE permit_file=? LIMIT 1", (permit_file,)).fetchone():
            raise ValueError("PERMIT_PATH_ALREADY_USED")
        job_id = uuid.uuid4().hex
        conn.execute("""INSERT INTO jobs (job_id,run_at_ms,port,tool,arguments_json,
            permit_file,status,created_at_ms) VALUES (?,?,?,?,?,?,'PENDING',?)""",
            (job_id, now, row["port"], row["tool"], row["arguments_json"], permit_file, now))
        conn.execute("""UPDATE recurring_schedules SET next_due_ms=?,
            last_issued_at_ms=?,last_job_id=?,skipped_intervals=skipped_intervals+?
            WHERE schedule_id=?""", (next_due, now, job_id, elapsed, schedule_id))
        return {"status": "RELEASED", "schedule_id": schedule_id, "job_id": job_id,
                "skipped": elapsed, "next_due_ms": next_due}


def skip_missed(db_path: str | Path, schedule_id: str, *, now_ms: int | None = None) -> dict:
    """Fast-forward expired windows without requesting or consuming a permit.

    Does not skip a currently eligible window. Never queues an execution.
    """
    now = _clock(now_ms)
    if type(schedule_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", schedule_id):
        raise ValueError("Invalid schedule ID")
    with open_db(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        _advance_clock(conn, now)
        row = conn.execute(
            "SELECT * FROM recurring_schedules WHERE schedule_id=?", (schedule_id,)
        ).fetchone()
        if row is None:
            raise ValueError("SCHEDULE_NOT_AVAILABLE")
        due = row['next_due_ms']
        if now < due:
            return {'status': 'NOT_DUE', 'schedule_id': schedule_id, 'next_due_ms': due}
        interval = row['interval_ms']
        elapsed = (now - due) // interval
        current_due = due + elapsed * interval
        expired = now - current_due > row['window_ms']
        missed = elapsed + int(expired)
        next_due = current_due + (interval if expired else 0)
        if next_due > MAX_TIME_MS:
            raise ValueError('SCHEDULE_TIME_OVERFLOW')
        if missed:
            conn.execute('''UPDATE recurring_schedules SET next_due_ms=?,
                skipped_intervals=skipped_intervals+? WHERE schedule_id=?''',
                (next_due, missed, schedule_id))
        return {'status':'SKIPPED' if missed else 'CURRENT_WINDOW',
                'schedule_id':schedule_id, 'skipped':missed,
                'next_due_ms':next_due}
