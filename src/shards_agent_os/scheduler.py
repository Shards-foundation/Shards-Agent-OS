"""Persistent, fail-closed one-shot scheduler for Shards-Kernel's local MCP client."""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Callable

from .storage import open_db as _connect

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
    if not isinstance(permit_file, str) or not os.path.isabs(permit_file):
        raise ValueError("An absolute, independently issued permit file path is required")
    # Do not open or copy permits into the job store. The kernel CLI enforces
    # ownership, symlink and 0600 checks immediately before use.
    if len(json.dumps(arguments, allow_nan=False)) > 4096:
        raise ValueError("Arguments exceed the first-release size limit")


def enqueue(
    db_path: str | os.PathLike[str], *, run_at_ms: int, port: int, tool: str,
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


def list_jobs(db_path: str | os.PathLike[str]) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT job_id, run_at_ms, tool, status, result_json FROM jobs ORDER BY run_at_ms, job_id"
        ).fetchall()
        return [dict(row) for row in rows]


def cancel_pending(db_path: str | os.PathLike[str], job_id: str) -> bool:
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
    # Do not inherit operator/issuer secrets or unrelated service credentials.
    # Only the agent bearer and minimal interpreter environment cross into MCP.
    env = {key: os.environ[key] for key in (
        "SHARDS_KERNEL_AGENT_TOKEN", "PATH", "HOME",
        "VIRTUAL_ENV", "LANG", "LC_ALL", "SYSTEMROOT",
    ) if key in os.environ}
    completed = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout_s,
        check=False, env=env,
    )
    return completed.returncode, completed.stdout


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate receipt key')
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError('Non-finite JSON constant')


def _result_state(job: Job, returncode: int, stdout: str) -> tuple[str, dict]:
    if len(stdout.encode("utf-8")) > 65536:
        return "UNKNOWN", {"error": "Oversized or unverified kernel receipt"}
    try:
        receipt = json.loads(stdout, object_pairs_hook=_unique_json_pairs,
                             parse_constant=_reject_json_constant)
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
        if job.tool == "echo":
            if type(result) is not str or result != job.arguments['text']:
                return "UNKNOWN", {"error": "Invalid or mismatched echo result"}
        if job.tool == "add":
            if (type(result) not in (int, float) or not math.isfinite(result)
                    or result != job.arguments['a'] + job.arguments['b']):
                return "UNKNOWN", {"error": "Invalid or mismatched add result"}
        return "SUCCEEDED", {"decision": "ALLOW", "request_id": request_id, "result": result}
    return "UNKNOWN", {"error": "Unverified execution outcome"}


def run_once(
    db_path: str | os.PathLike[str], *, now_ms: int | None = None, timeout_s: float = 30.0,
    runner: Callable[[Job, float], tuple[int, str]] = _invoke_kernel,
    max_running: int = 1,
) -> dict | None:
    """Atomically claim one due job; never auto-retry RUNNING/UNKNOWN jobs.

    If this process crashes after claim, RUNNING remains visible for manual
    reconciliation. A timeout does not prove the operator stopped executing.
    """
    if type(timeout_s) not in (int, float) or timeout_s <= 0 or not math.isfinite(timeout_s):
        raise ValueError("timeout_s must be positive and finite")
    if type(max_running) is not int or max_running < 1 or max_running > 64:
        raise ValueError("max_running must be an integer between 1 and 64")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        # The local operator HALT latch and the running quota are checked in
        # the same write transaction as the claim. A crash leaves RUNNING
        # jobs occupying capacity until an operator reconciles them.
        control = conn.execute("SELECT halted FROM control WHERE singleton=1").fetchone()
        if control["halted"]:
            conn.commit()
            return None
        running = conn.execute("SELECT COUNT(*) FROM jobs WHERE status='RUNNING'").fetchone()[0]
        if running >= max_running:
            conn.commit()
            return None
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


def reconcile_unknown(db_path: str | os.PathLike[str], job_id: str, incident_id: str) -> bool:
    """Classify a stuck RUNNING job as UNKNOWN, never retryable.

    This does not verify kernel evidence or prove that work has stopped.
    A trusted operator must verify both out of band before recovering capacity.
    """
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{2,79}', incident_id):
        raise ValueError('Provide a 3..80 character incident reference')
    if not re.fullmatch(r'[0-9a-f]{32}', job_id):
        raise ValueError('Invalid job ID')
    result = json.dumps({'error':'Operator moved RUNNING to UNKNOWN', 'incident_id':incident_id})
    with _connect(db_path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        return conn.execute(
            "UPDATE jobs SET status='UNKNOWN',result_json=?,finished_at_ms=? WHERE job_id=? AND status='RUNNING'",
            (result,int(time.time()*1000),job_id)
        ).rowcount == 1
