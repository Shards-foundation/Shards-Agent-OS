"""Durable, non-replaying Agent OS queue for independently approved gVisor work.

This runs ONLY under the unprivileged agent UID. It cannot issue a permit,
access Docker, override the trusted broker's actor, or broaden approved args.
Every claim is committed before calling the separately privileged broker.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import signal
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .sandbox_client import _private_json, call_broker
from .sandbox_executor import ExecutionSpec
from .storage import open_db

_STATES = frozenset(("PENDING", "RUNNING", "SUCCEEDED", "FAILED", "DENIED", "UNKNOWN", "CANCELLED"))
_FIELDS = frozenset(("image", "argv", "timeout_seconds", "memory_megabytes", "cpu_millicores", "pids_limit"))
_MAX_RESPONSE = 96 * 1024
_MAX_OUTPUT = 8192
_DEFAULT_SOCKET = "/run/shards-sandbox/broker.sock"


@dataclass(frozen=True)
class SandboxJob:
    job_id: str
    run_at_ms: int
    socket_path: str
    operator_uid: int
    arguments: dict[str, Any]
    permit_file: str


def _validate_arguments(arguments: dict[str, Any]) -> ExecutionSpec:
    if type(arguments) is not dict or set(arguments) != _FIELDS:
        raise ValueError("sandbox.exec requires all six exact signed arguments")
    if type(arguments["argv"]) is not list:
        raise ValueError("sandbox argv must be a JSON array")
    spec = ExecutionSpec(
        image=arguments["image"], argv=tuple(arguments["argv"]),
        timeout_seconds=arguments["timeout_seconds"],
        memory_megabytes=arguments["memory_megabytes"],
        cpu_millicores=arguments["cpu_millicores"],
        pids_limit=arguments["pids_limit"],
    )
    return spec


def _check_endpoint(socket_path: str, operator_uid: int, permit_file: str) -> None:
    if (
        type(socket_path) is not str
        or socket_path != _DEFAULT_SOCKET
        or type(operator_uid) is not int
        or operator_uid < 1
        or operator_uid == os.geteuid()
    ):
        raise ValueError("Use the separately privileged pinned local sandbox broker")
    if type(permit_file) is not str or not os.path.isabs(permit_file):
        raise ValueError("An absolute independently signed permit path is required")
    if len(permit_file) > 2048:
        raise ValueError("Permit path too long")


def enqueue_sandbox(
    db_path: str | os.PathLike[str], *, run_at_ms: int,
    arguments: dict[str, Any], permit_file: str, operator_uid: int,
    socket_path: str = _DEFAULT_SOCKET, now_ms: int | None = None,
) -> str:
    """Queue a permission *attempt*, not a pre-authorised capability."""
    spec = _validate_arguments(arguments)
    _check_endpoint(socket_path, operator_uid, permit_file)
    if type(run_at_ms) is not int or run_at_ms < 0:
        raise ValueError("run_at_ms must be non-negative")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if type(now) is not int or now < 0:
        raise ValueError("Invalid enqueue clock")
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > 16384:
        raise ValueError("Sandbox request too large")
    job_id = uuid.uuid4().hex
    with open_db(db_path) as db:
        db.execute(
            "INSERT INTO sandbox_jobs "
            "(job_id,run_at_ms,socket_path,operator_uid,arguments_json,permit_file,"
            "status,created_at_ms) VALUES (?,?,?,?,?,?,'PENDING',?)",
            (job_id, run_at_ms, socket_path, operator_uid, encoded, permit_file, now),
        )
    return job_id


def list_sandbox_jobs(db_path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Never reveal signer, permit bytes, private path or agent OS credentials."""
    with open_db(db_path) as db:
        rows = db.execute(
            "SELECT job_id,run_at_ms,status,result_json FROM sandbox_jobs "
            "ORDER BY run_at_ms,job_id"
        ).fetchall()
        return [
            {"job_id": row["job_id"], "run_at_ms": row["run_at_ms"],
             "status": row["status"], "result": (
                 json.loads(row["result_json"]) if row["result_json"] else None
             )}
            for row in rows
        ]


def cancel_sandbox_pending(db_path: str | os.PathLike[str], job_id: str) -> bool:
    if type(job_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("Invalid sandbox job ID")
    with open_db(db_path) as db:
        row = db.execute(
            "UPDATE sandbox_jobs SET status='CANCELLED', finished_at_ms=? "
            "WHERE job_id=? AND status='PENDING'",
            (int(time.time()*1000), job_id),
        )
        return row.rowcount == 1


def reconcile_sandbox_unknown(
    db_path: str | os.PathLike[str], *, job_id: str, incident_id: str,
) -> bool:
    """Administrative classification; requires independently inspected evidence."""
    if type(job_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("Invalid sandbox job ID")
    if type(incident_id) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,79}", incident_id):
        raise ValueError("Provide an incident identifier (3-80 safe characters)")
    result = json.dumps({"error": "Manually reconciled to UNKNOWN", "incident_id": incident_id})
    with open_db(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "UPDATE sandbox_jobs SET status='UNKNOWN',result_json=?,finished_at_ms=? "
            "WHERE job_id=? AND status='RUNNING'",
            (result, int(time.time()*1000), job_id),
        )
        return row.rowcount == 1


def _invoke(job: SandboxJob, timeout_s: float) -> dict[str, Any]:
    """Read signed permit only at use time, never store it in the queue."""
    spec = _validate_arguments(job.arguments)
    # The browser/agent/scheduler may have been restarted since enqueue.
    _check_endpoint(job.socket_path, job.operator_uid, job.permit_file)
    permit = _private_json(job.permit_file)
    return call_broker(
        socket_path=job.socket_path,
        expected_operator_uid=job.operator_uid,
        arguments=job.arguments, permit=permit,
        timeout_s=min(timeout_s, 180),
    )


def _summarise(response: Any, job: SandboxJob) -> tuple[str, dict[str, Any]]:
    """Never misclassify an uncorrelated or ambiguous ALLOW as success."""
    if type(response) is not dict:
        return "UNKNOWN", {"error": "Unrecognised broker reply"}
    try:
        if len(json.dumps(response, allow_nan=False).encode("utf-8")) > _MAX_RESPONSE:
            raise ValueError("Oversized response")
    except (ValueError, TypeError, OverflowError):
        return "UNKNOWN", {"error": "Unverifiable broker response"}
    if response.get("decision") == "DENY" and type(response.get("error")) is str:
        return "DENIED", {"decision": "DENY"}
    if response.get("decision") != "ALLOW" or type(response.get("result")) is not dict:
        return "UNKNOWN", {"error": "Execution outcome uncertain"}
    raw = response["result"]
    spec = _validate_arguments(job.arguments)
    if (
        raw.get("fingerprint") != spec.fingerprint()
        or raw.get("cleanup_confirmed") is not True
        or type(raw.get("status")) is not str
        or raw["status"] not in ("EXITED", "PROCESS_ERROR", "TIMEOUT", "OUTPUT_LIMIT")
        or type(raw.get("duration_ms")) is not int
        or raw["duration_ms"] < 0
        or (raw.get("exit_code") is not None and type(raw["exit_code"]) is not int)
        or type(raw.get("stdout")) is not str
        or type(raw.get("stderr")) is not str
    ):
        return "UNKNOWN", {"error": "Uncorrelated or unverified sandbox execution"}
    status = "UNKNOWN"
    if raw["status"] == "EXITED" and raw["exit_code"] == 0:
        status = "SUCCEEDED"
    elif raw["status"] in ("PROCESS_ERROR", "TIMEOUT", "OUTPUT_LIMIT"):
        status = "FAILED"  # Failure is terminal: no automatic retry.
    result = {
        "decision": "ALLOW",
        "status": raw["status"],
        "exit_code": raw.get("exit_code"),
        "duration_ms": raw["duration_ms"],
        "fingerprint": raw["fingerprint"],
        "cleanup_confirmed": True,
    }
    for channel in ("stdout", "stderr"):
        value = raw[channel].encode("utf-8")
        result[channel] = value[:_MAX_OUTPUT].decode("utf-8", errors="replace")
        result[channel + "_sha256"] = hashlib.sha256(value).hexdigest()
        result[channel + "_truncated"] = len(value) > _MAX_OUTPUT
    return status, result


def run_sandbox_once(
    db_path: str | os.PathLike[str], *, now_ms: int | None = None,
    timeout_s: float = 150.0, max_running: int = 1,
    runner: Callable[[SandboxJob, float], dict[str, Any]] = _invoke,
) -> dict[str, Any] | None:
    """Claim one due job durably; halt/capacity guards include legacy MCP jobs.

    Process crash after claim leaves RUNNING. No implicit retries or cleanup of
    external effects; use the operator's durable gVisor orphan reconciler.
    """
    if type(timeout_s) not in (int, float) or not math.isfinite(timeout_s) or not 1 <= timeout_s <= 180:
        raise ValueError("Timeout must be finite 1-180 seconds")
    if type(max_running) is not int or not 1 <= max_running <= 64:
        raise ValueError("Concurrent claim cap must be 1-64")
    now = int(time.time()*1000) if now_ms is None else now_ms
    if type(now) is not int or now < 0:
        raise ValueError("Invalid worker clock")
    db = open_db(db_path)
    try:
        db.execute("BEGIN IMMEDIATE")
        control = db.execute("SELECT halted FROM control WHERE singleton=1").fetchone()
        if control is None or control["halted"]:
            db.commit()
            return None
        running = db.execute(
            "SELECT (SELECT COUNT(*) FROM sandbox_jobs WHERE status='RUNNING') + "
            "(SELECT COUNT(*) FROM jobs WHERE status='RUNNING')"
        ).fetchone()[0]
        if running >= max_running:
            db.commit()
            return None
        row = db.execute(
            "SELECT * FROM sandbox_jobs WHERE status='PENDING' AND run_at_ms<=? "
            "ORDER BY run_at_ms,job_id LIMIT 1", (now,),
        ).fetchone()
        if row is None:
            db.commit()
            return None
        db.execute(
            "UPDATE sandbox_jobs SET status='RUNNING',started_at_ms=? "
            "WHERE job_id=? AND status='PENDING'",
            (now, row["job_id"]),
        )
        db.commit()
        job = SandboxJob(
            job_id=row["job_id"], run_at_ms=row["run_at_ms"],
            socket_path=row["socket_path"], operator_uid=row["operator_uid"],
            arguments=json.loads(row["arguments_json"]),
            permit_file=row["permit_file"],
        )
        try:
            response = runner(job, timeout_s)
            status, details = _summarise(response, job)
        except Exception:
            status, details = "UNKNOWN", {"error": "Execution outcome uncertain"}
        db.execute(
            "UPDATE sandbox_jobs SET status=?,result_json=?,finished_at_ms=? "
            "WHERE job_id=? AND status='RUNNING'",
            (status, json.dumps(details, sort_keys=True), int(time.time()*1000), job.job_id),
        )
        db.commit()
        return {"job_id": job.job_id, "status": status, "receipt": details}
    finally:
        db.close()


def serve_sandbox(
    db_path: str | os.PathLike[str], *, poll_s: float = 1.0,
    timeout_s: float = 150.0, max_running: int = 1,
    stop: threading.Event | None = None,
    max_ticks: int | None = None,
) -> int:
    """Single-threaded, cooperative poller; no self-issued approval or replay."""
    if type(poll_s) not in (int, float) or not math.isfinite(poll_s) or not 0.05 <= poll_s <= 60:
        raise ValueError("Poll interval must be 0.05-60 seconds")
    if max_ticks is not None and (type(max_ticks) is not int or max_ticks < 0):
        raise ValueError("Invalid max ticks")
    event = stop if stop is not None else threading.Event()
    handlers = {}
    if stop is None and threading.current_thread() is threading.main_thread():
        def _stop(_signum, _frame):
            event.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, _stop)
    ticks = 0
    from .interrupts import control_state
    try:
        while not event.is_set():
            if control_state(db_path)["halted"]:
                break
            result = run_sandbox_once(
                db_path, timeout_s=timeout_s, max_running=max_running,
            )
            ticks += 1
            if max_ticks is not None and ticks >= max_ticks:
                break
            if result is None:
                event.wait(poll_s)
        return ticks
    finally:
        for sig, previous in handlers.items():
            signal.signal(sig, previous)
