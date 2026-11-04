"""Persistent, fail-closed one-shot scheduler for Shards-Kernel's local MCP client."""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

STATES = frozenset({"PENDING", "RUNNING", "SUCCEEDED", "DENIED", "UNKNOWN", "CANCELLED"})


@dataclass(frozen=True)
class Job:
    job_id: str
    run_at_ms: int
    port: int
    tool: str
    arguments: dict
    permit_file: str
    status: str


def _validate_job(tool: str, arguments: dict, port: int, permit_file: str) -> None:
    if tool not in {"echo", "add"} or type(arguments) is not dict:
        raise ValueError("Only echo/add with exact argument schemas are supported")
    if tool == "echo":
        if set(arguments) != {"text"} or type(arguments["text"]) is not str:
            raise ValueError("echo requires exactly {'text': str}")
    else:
        if set(arguments) != {"a", "b"} or any(type(arguments[k]) not in (int, float) or not math.isfinite(arguments[k]) for k in ("a", "b")):
            raise ValueError("add requires exactly two finite numbers")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid loopback operator port")
    if not isinstance(permit_file, str) or not Path(permit_file).is_absolute():
        raise ValueError("An absolute, independently issued permit file path is required")
    # Do not open or copy permits into the job store. The kernel CLI enforces
    # ownership, symlink and 0600 checks immediately before use.
    if len(json.dumps(arguments, allow_nan=False)) > 4096:
        raise ValueError("Arguments exceed the first-release size limit")


def _connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.is_absolute():
        raise ValueError("Database path must be absolute")
    if not path.parent.is_dir():
        raise ValueError("Create the state directory before starting")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or (hasattr(os, "geteuid") and info.st_uid != os.geteuid()):
            raise PermissionError("State database must be owned by this user and mode 0600")
    finally:
        os.close(fd)
    connection = sqlite3.connect(str(path), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("""CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        run_at_ms INTEGER NOT NULL,
        port INTEGER NOT NULL,
        tool TEXT NOT NULL,
        arguments_json TEXT NOT NULL,
        permit_file TEXT NOT NULL,
        status TEXT NOT NULL,
        result_json TEXT,
        created_at_ms INTEGER NOT NULL,
        started_at_ms INTEGER,
        finished_at_ms INTEGER
    )""")
    connection.commit()
    return connection


def enqueue(
    db_path: str | Path, *, run_at_ms: int, port: int, tool: str,
    arguments: dict, permit_file: str, now_ms: int | None = None,
) -> str:
    _validate_job(tool, arguments, port, permit_file)
    if type(run_at_ms) is not int or run_at_ms < 0:
        raise ValueError("run_at_ms must be a non-negative integer")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    job_id = uuid.uuid4().hex
    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO jobs (job_id, run_at_ms, port, tool, arguments_json,
            permit_file, status, created_at_ms) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?)""",
            (job_id, run_at_ms, port, tool,
             json.dumps(arguments, sort_keys=True, separators=(",", ":"), allow_nan=False),
             permit_file, now),
        )
    return job_id


def list_jobs(db_path: str | Path) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT job_id, run_at_ms, tool, status, result_json FROM jobs ORDER BY run_at_ms, job_id"
        ).fetchall()
        return [dict(row) for row in rows]


def cancel_pending(db_path: str | Path, job_id: str) -> bool:
    """Cancel only PENDING. A RUNNING process may already have effects."""
    with _connect(db_path) as conn:
        result = conn.execute(
            "UPDATE jobs SET status='CANCELLED', finished_at_ms=? WHERE job_id=? AND status='PENDING'",
            (int(time.time() * 1000), job_id),
        )
        return result.rowcount == 1


def _invoke_kernel(job: Job, timeout_s: float) -> tuple[int, str]:
    """Use the installed kernel CLI; never construct a permit or use shell=True."""
    args = [
        sys.executable, "-m", "shards_kernel", "mcp-call",
        "--port", str(job.port), "--tool", job.tool,
        "--arguments-json", json.dumps(job.arguments, sort_keys=True, separators=(",", ":")),
        "--permit-file", job.permit_file,
    ]
    completed = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout_s, check=False,
    )
    return completed.returncode, completed.stdout


def _result_state(job: Job, returncode: int, stdout: str) -> tuple[str, dict]:
    if len(stdout.encode("utf-8")) > 65536:
        return "UNKNOWN", {"error": "Oversized or unverified kernel receipt"}
    try:
        receipt = json.loads(stdout)
        if type(receipt) is not dict:
            raise ValueError("Invalid receipt")
    except (ValueError, TypeError):
        return "UNKNOWN", {"error": "Invalid or missing kernel receipt"}
    if returncode == 2 and receipt.get("decision") == "DENY":
        return "DENIED", {"decision": "DENY"}
    if returncode == 0 and receipt.get("decision") == "ALLOW":
        request_id = receipt.get("request_id")
        result = receipt.get("result")
        if not isinstance(request_id, str) or re.fullmatch(r"mcp-relay-[0-9a-f]{32}", request_id) is None:
            return "UNKNOWN", {"error": "Uncorrelated ALLOW receipt"}
        if job.tool == "echo" and type(result) is not str:
            return "UNKNOWN", {"error": "Invalid echo result"}
        if job.tool == "add" and (type(result) not in (int, float) or not math.isfinite(result)):
            return "UNKNOWN", {"error": "Invalid add result"}
        return "SUCCEEDED", {"decision": "ALLOW", "request_id": request_id, "result": result}
    return "UNKNOWN", {"error": "Unverified execution outcome"}


def run_once(
    db_path: str | Path, *, now_ms: int | None = None, timeout_s: float = 30.0,
    runner: Callable[[Job, float], tuple[int, str]] = _invoke_kernel,
) -> dict | None:
    """Atomically claim one due job; never auto-retry RUNNING/UNKNOWN jobs.

    If this process crashes after claim, RUNNING remains visible for manual
    reconciliation. A timeout does not prove the operator stopped executing.
    """
    if timeout_s <= 0 or not math.isfinite(timeout_s):
        raise ValueError("timeout_s must be positive and finite")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM jobs WHERE status='PENDING' AND run_at_ms <= ? ORDER BY run_at_ms, job_id LIMIT 1",
            (now,),
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        conn.execute("UPDATE jobs SET status='RUNNING', started_at_ms=? WHERE job_id=? AND status='PENDING'", (now, row["job_id"]))
        conn.commit()
        job = Job(
            job_id=row["job_id"], run_at_ms=row["run_at_ms"], port=row["port"],
            tool=row["tool"], arguments=json.loads(row["arguments_json"]),
            permit_file=row["permit_file"], status="RUNNING",
        )
        try:
            returncode, output = runner(job, timeout_s)
            status, result = _result_state(job, returncode, output)
        except Exception:
            # Do not automatically retry: the call may have reached the operator.
            status, result = "UNKNOWN", {"error": "Execution outcome uncertain"}
        conn.execute(
            "UPDATE jobs SET status=?, result_json=?, finished_at_ms=? WHERE job_id=? AND status='RUNNING'",
            (status, json.dumps(result, sort_keys=True), int(time.time() * 1000), job.job_id),
        )
        conn.commit()
        return {"job_id": job.job_id, "status": status, "receipt": result}
    finally:
        conn.close()
