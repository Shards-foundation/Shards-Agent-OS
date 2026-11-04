"""Durable, fail-closed multi-step orchestration atop Shards Agent OS.

This is deliberately NOT a permit issuer, AI reasoning engine, or tool executor.
It atomically binds each approved stage to the existing kernel-governed OS queue.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any

from .scheduler import _validate_job
from .storage import open_db

_TASK_STATES = frozenset({"WAITING_PERMIT", "QUEUED", "RUNNING", "SUCCEEDED", "DENIED", "UNKNOWN", "CANCELLED"})
_STEP_STATES = _TASK_STATES
_TERMINAL = frozenset({"SUCCEEDED", "DENIED", "UNKNOWN", "CANCELLED"})
_JOB_TO_STEP = {
    "PENDING": "QUEUED", "RUNNING": "RUNNING", "SUCCEEDED": "SUCCEEDED",
    "DENIED": "DENIED", "UNKNOWN": "UNKNOWN", "CANCELLED": "CANCELLED",
}


def _connect(db_path: str):
    conn = open_db(db_path)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS harness_tasks (
            task_id TEXT PRIMARY KEY, name TEXT NOT NULL,
            status TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS harness_steps (
            task_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
            tool TEXT NOT NULL, port INTEGER NOT NULL, arguments_json TEXT NOT NULL,
            status TEXT NOT NULL, job_id TEXT UNIQUE,
            PRIMARY KEY(task_id,ordinal),
            FOREIGN KEY(task_id) REFERENCES harness_tasks(task_id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS harness_read_jobs (
            job_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
            repository TEXT NOT NULL, status TEXT NOT NULL,
            report_json TEXT, root_hash TEXT,
            created_at_ms INTEGER NOT NULL, started_at_ms INTEGER, finished_at_ms INTEGER,
            UNIQUE(task_id,ordinal),
            FOREIGN KEY(task_id,ordinal) REFERENCES harness_steps(task_id,ordinal))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS harness_read_evidence (
            job_id TEXT PRIMARY KEY, evidence_json TEXT NOT NULL,
            FOREIGN KEY(job_id) REFERENCES harness_read_jobs(job_id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS harness_read_incidents (
            job_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
            reconciled_at_ms INTEGER NOT NULL,
            FOREIGN KEY(job_id) REFERENCES harness_read_jobs(job_id))""")
        conn.commit()
        return conn
    except BaseException:
        conn.close()
        raise


def _now_ms() -> int:
    return int(time.time() * 1000)


_READ_TOOL = "github.list_workflow_runs"
_REPO_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")


def _validate_read_step(tool: object, port: object, arguments: object) -> None:
    if tool != _READ_TOOL or type(port) is not int or port != 0:
        raise ValueError("Unsupported read-only step")
    if type(arguments) is not dict or set(arguments) != {"repository"}:
        raise ValueError("Read step requires exactly a repository")
    repo = arguments["repository"]
    if type(repo) is not str or not _REPO_NAME.fullmatch(repo):
        raise ValueError("Invalid repository")
    if any(p in (".", "..") or p.startswith(".") for p in repo.split("/")):
        raise ValueError("Invalid repository component")


def _steps_checked(steps: list[dict[str, Any]]) -> list[tuple[str, int, str]]:
    if type(steps) is not list or not 1 <= len(steps) <= 32:
        raise ValueError("Supply between 1 and 32 steps")
    checked = []
    for item in steps:
        if type(item) is not dict or set(item) != {"tool", "port", "arguments"}:
            raise ValueError("Step must contain exactly tool, port and arguments")
        tool, port, args = item["tool"], item["port"], item["arguments"]
        if tool == _READ_TOOL:
            _validate_read_step(tool, port, args)
        else:
            _validate_job(tool, args, port, "/nonexistent/permit-not-yet-issued.json")
        checked.append((tool, port, json.dumps(args, sort_keys=True, separators=(",", ":"), allow_nan=False)))
    return checked


def create_task(db_path: str, *, name: str, steps: list[dict[str, Any]]) -> str:
    """Store intended stages. This does not issue permissions or queue executions."""
    if type(name) is not str or not 1 <= len(name.strip()) <= 160:
        raise ValueError("Task name must contain 1..160 characters")
    checked = _steps_checked(steps)
    task_id, now = uuid.uuid4().hex, _now_ms()
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO harness_tasks VALUES (?,?,?,?,?)", (task_id, name, "WAITING_PERMIT", now, now))
        conn.executemany(
            "INSERT INTO harness_steps (task_id,ordinal,tool,port,arguments_json,status) "
            "VALUES (?,?,?,?,?,'WAITING_PERMIT')",
            [(task_id, i, tool, port, args_json) for i, (tool, port, args_json) in enumerate(checked)],
        )
    return task_id


def get_task(db_path: str, task_id: str) -> dict[str, Any]:
    """Return a deliberately sanitised state snapshot: never permit paths or tokens."""
    with _connect(db_path) as conn:
        task = conn.execute(
            "SELECT task_id,name,status,created_at_ms,updated_at_ms FROM harness_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if task is None:
            raise ValueError("Unknown task")
        rows = conn.execute(
            "SELECT ordinal,tool,port,status,job_id FROM harness_steps WHERE task_id=? ORDER BY ordinal", (task_id,)
        ).fetchall()
        return {**dict(task), "steps": [dict(row) for row in rows]}


def list_tasks(db_path: str) -> list[dict[str, Any]]:
    with _connect(db_path) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT task_id,name,status,created_at_ms,updated_at_ms FROM harness_tasks "
            "ORDER BY created_at_ms DESC,task_id DESC LIMIT 200"
        ).fetchall()]


def _refresh_locked(conn, task_id: str) -> str:
    parent = conn.execute("SELECT status FROM harness_tasks WHERE task_id=?", (task_id,)).fetchone()
    if parent is None:
        raise ValueError("Unknown task")
    stages = conn.execute(
        "SELECT ordinal,status,job_id,tool FROM harness_steps WHERE task_id=? ORDER BY ordinal", (task_id,)
    ).fetchall()
    states = []
    for stage in stages:
        new = stage["status"]
        if stage["job_id"]:
            table = "harness_read_jobs" if stage["tool"] == _READ_TOOL else "jobs"
            job = conn.execute(
                f"SELECT status FROM {table} WHERE job_id=?", (stage["job_id"],)
            ).fetchone()
            new = _JOB_TO_STEP.get(job["status"]) if job else None
            if new is None:
                new = "UNKNOWN"  # Deleted or unrecognised job: never assume success.
            if new != stage["status"]:
                conn.execute(
                    "UPDATE harness_steps SET status=? WHERE task_id=? AND ordinal=?",
                    (new, task_id, stage["ordinal"]),
                )
        states.append(new)
    if not states:
        raise RuntimeError("Corrupt task: no steps")
    if "UNKNOWN" in states:
        status = "UNKNOWN"
    elif "DENIED" in states:
        status = "DENIED"
    elif "CANCELLED" in states:
        status = "CANCELLED"
    elif all(state == "SUCCEEDED" for state in states):
        status = "SUCCEEDED"
    elif "RUNNING" in states:
        status = "RUNNING"
    elif "QUEUED" in states:
        status = "QUEUED"
    else:
        status = "WAITING_PERMIT"
    if parent["status"] != status:
        conn.execute("UPDATE harness_tasks SET status=?,updated_at_ms=? WHERE task_id=?",
                     (status, _now_ms(), task_id))
    return status


def refresh_task(db_path: str, task_id: str) -> dict[str, Any]:
    """Reconcile with durable OS jobs; never re-execute uncertain operations."""
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        _refresh_locked(conn, task_id)
    return get_task(db_path, task_id)


def release_step(db_path: str, *, task_id: str, ordinal: int, permit_file: str) -> str:
    """Atomically enqueue a pre-authorised stage in the existing OS job store.

    Only Shards-Kernel verifies the signature, subject and exact permit scope.
    A permit path here is an intent to attempt execution, NOT evidence of ALLOW.
    """
    if type(ordinal) is not int or ordinal < 0:
        raise ValueError("Invalid step ordinal")
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        state = _refresh_locked(conn, task_id)
        if state in _TERMINAL:
            raise ValueError("Task is terminal; no implicit replay")
        halted = conn.execute("SELECT halted FROM control WHERE singleton=1").fetchone()
        if halted is None or halted["halted"]:
            raise ValueError("Dispatch halted or control missing")
        steps = conn.execute(
            "SELECT ordinal,status,job_id,tool,port,arguments_json FROM harness_steps "
            "WHERE task_id=? ORDER BY ordinal", (task_id,)
        ).fetchall()
        if ordinal >= len(steps) or steps[ordinal]["ordinal"] != ordinal:
            raise ValueError("Unknown step")
        if any(item["status"] != "SUCCEEDED" for item in steps[:ordinal]):
            raise ValueError("Previous stages have not succeeded")
        step = steps[ordinal]
        if step["status"] != "WAITING_PERMIT" or step["job_id"] is not None:
            raise ValueError("Step already dispatched or not eligible")
        if step["tool"] == _READ_TOOL:
            raise ValueError("Read-only steps require release_read_step")
        args = json.loads(step["arguments_json"])
        _validate_job(step["tool"], args, step["port"], permit_file)
        if conn.execute("SELECT 1 FROM jobs WHERE permit_file=? LIMIT 1", (permit_file,)).fetchone():
            raise ValueError("Permit path already allocated to a job")
        job_id, now = uuid.uuid4().hex, _now_ms()
        conn.execute(
            "INSERT INTO jobs (job_id,run_at_ms,port,tool,arguments_json,permit_file,status,created_at_ms) "
            "VALUES (?,?,?,?,?,?,'PENDING',?)",
            (job_id, now, step["port"], step["tool"], step["arguments_json"], permit_file, now),
        )
        conn.execute(
            "UPDATE harness_steps SET status='QUEUED',job_id=? WHERE task_id=? AND ordinal=?",
            (job_id, task_id, ordinal),
        )
        conn.execute(
            "UPDATE harness_tasks SET status='QUEUED',updated_at_ms=? WHERE task_id=?",
            (now, task_id),
        )
        return job_id
