"""Durable, per-owner conversation, turn, receipt and budget state.

This module stores *only* facts that are safe to show a signed-in owner:
questions, final replies, tool names, decisions, job identifiers and coarse
error codes. It never stores permits, bearer tokens, provider API keys or raw
model prompts.

A turn is written as ``RUNNING`` *before* any model or tool work happens, so a
process crash leaves visible evidence instead of a silent gap. Recovery moves
those rows to ``UNKNOWN`` and never re-executes them.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any

from .storage import open_db

TURN_STATES = frozenset({"RUNNING", "SUCCEEDED", "DENIED", "FAILED", "UNKNOWN"})
TERMINAL_TURN_STATES = frozenset({"SUCCEEDED", "DENIED", "FAILED", "UNKNOWN"})

_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_MAX_QUESTION = 2000
_MAX_REPLY = 8000
_MAX_RECEIPT_BYTES = 16384


def _connect(db_path: str):
    conn = open_db(db_path)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS agent_conversations (
            conversation_id TEXT PRIMARY KEY, actor TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS agent_turns (
            turn_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL,
            actor TEXT NOT NULL, question TEXT NOT NULL, status TEXT NOT NULL,
            provider TEXT, model TEXT, model_latency_ms INTEGER,
            reply TEXT, tool_name TEXT, tool_status TEXT, grant_id TEXT,
            job_id TEXT, error_code TEXT,
            created_at_ms INTEGER NOT NULL, finished_at_ms INTEGER)""")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_turns_actor "
            "ON agent_turns(actor, created_at_ms)"
        )
        conn.execute("""CREATE TABLE IF NOT EXISTS agent_receipts (
            receipt_id TEXT PRIMARY KEY, turn_id TEXT NOT NULL,
            actor TEXT NOT NULL, kind TEXT NOT NULL, payload_json TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL)""")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_receipts_turn "
            "ON agent_receipts(turn_id, created_at_ms)"
        )
        conn.execute("""CREATE TABLE IF NOT EXISTS agent_budgets (
            actor TEXT PRIMARY KEY, window_start_ms INTEGER NOT NULL,
            count INTEGER NOT NULL)""")
        conn.commit()
        return conn
    except BaseException:
        conn.close()
        raise


def _now_ms() -> int:
    return int(time.time() * 1000)


def _require_hex32(value: object, label: str) -> str:
    if type(value) is not str or not _HEX32.fullmatch(value):
        raise ValueError(f"Invalid {label}")
    return value


def create_conversation(db_path: str, *, actor: str) -> str:
    if type(actor) is not str or not 1 <= len(actor) <= 254:
        raise ValueError("Invalid actor")
    conversation_id, now = uuid.uuid4().hex, _now_ms()
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO agent_conversations VALUES (?,?,?,?)",
            (conversation_id, actor, now, now),
        )
    return conversation_id


def conversation_belongs_to(db_path: str, *, conversation_id: str, actor: str) -> bool:
    _require_hex32(conversation_id, "conversation ID")
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT actor FROM agent_conversations WHERE conversation_id=?",
            (conversation_id,),
        ).fetchone()
    return row is not None and row["actor"] == actor


def start_turn(db_path: str, *, conversation_id: str, actor: str, question: str) -> str:
    """Persist a RUNNING turn before any model or tool work is attempted."""
    _require_hex32(conversation_id, "conversation ID")
    if type(question) is not str or not 1 <= len(question.strip()) <= _MAX_QUESTION:
        raise ValueError("Question must contain 1..2000 characters")
    if type(actor) is not str or not actor:
        raise ValueError("Invalid actor")
    turn_id, now = uuid.uuid4().hex, _now_ms()
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        owner = conn.execute(
            "SELECT actor FROM agent_conversations WHERE conversation_id=?",
            (conversation_id,),
        ).fetchone()
        if owner is None or owner["actor"] != actor:
            raise ValueError("Unknown conversation for this owner")
        conn.execute(
            "INSERT INTO agent_turns (turn_id,conversation_id,actor,question,status,created_at_ms) "
            "VALUES (?,?,?,?,'RUNNING',?)",
            (turn_id, conversation_id, actor, question.strip(), now),
        )
        conn.execute(
            "UPDATE agent_conversations SET updated_at_ms=? WHERE conversation_id=?",
            (now, conversation_id),
        )
    return turn_id


def finish_turn(
    db_path: str, *, turn_id: str, status: str, provider: str | None = None,
    model: str | None = None, model_latency_ms: int | None = None,
    reply: str | None = None, tool_name: str | None = None,
    tool_status: str | None = None, grant_id: str | None = None,
    job_id: str | None = None, error_code: str | None = None,
) -> bool:
    """Move one RUNNING turn to a terminal state exactly once."""
    _require_hex32(turn_id, "turn ID")
    if status not in TERMINAL_TURN_STATES:
        raise ValueError("Invalid terminal turn state")
    if reply is not None and len(reply) > _MAX_REPLY:
        reply = reply[:_MAX_REPLY]
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            "UPDATE agent_turns SET status=?,provider=?,model=?,model_latency_ms=?,"
            "reply=?,tool_name=?,tool_status=?,grant_id=?,job_id=?,error_code=?,"
            "finished_at_ms=? WHERE turn_id=? AND status='RUNNING'",
            (status, provider, model, model_latency_ms, reply, tool_name,
             tool_status, grant_id, job_id, error_code, _now_ms(), turn_id),
        ).rowcount
    return changed == 1


def add_receipt(db_path: str, *, turn_id: str, actor: str, kind: str, payload: dict) -> str:
    """Append a bounded, sanitised receipt. Raises if the payload is unsafe."""
    _require_hex32(turn_id, "turn ID")
    if type(kind) is not str or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", kind):
        raise ValueError("Invalid receipt kind")
    if type(payload) is not dict:
        raise ValueError("Receipt payload must be an object")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > _MAX_RECEIPT_BYTES:
        raise ValueError("Receipt payload too large")
    receipt_id, now = uuid.uuid4().hex, _now_ms()
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO agent_receipts VALUES (?,?,?,?,?,?)",
            (receipt_id, turn_id, actor, kind, encoded, now),
        )
    return receipt_id


def get_turn(db_path: str, *, turn_id: str, actor: str) -> dict[str, Any]:
    _require_hex32(turn_id, "turn ID")
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM agent_turns WHERE turn_id=? AND actor=?", (turn_id, actor)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown turn for this owner")
        receipts = conn.execute(
            "SELECT receipt_id,kind,payload_json,created_at_ms FROM agent_receipts "
            "WHERE turn_id=? ORDER BY created_at_ms, receipt_id",
            (turn_id,),
        ).fetchall()
    result = dict(row)
    result["receipts"] = [
        {
            "receipt_id": item["receipt_id"],
            "kind": item["kind"],
            "payload": json.loads(item["payload_json"]),
            "created_at_ms": item["created_at_ms"],
        }
        for item in receipts
    ]
    return result


def list_turns(db_path: str, *, actor: str, conversation_id: str, limit: int = 50) -> list[dict]:
    """Return this owner's turns for one conversation, newest last."""
    _require_hex32(conversation_id, "conversation ID")
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("Invalid limit")
    with _connect(db_path) as conn:
        if not conversation_belongs_to(db_path, conversation_id=conversation_id, actor=actor):
            raise ValueError("Unknown conversation for this owner")
        rows = conn.execute(
            "SELECT turn_id,question,status,provider,model,model_latency_ms,reply,"
            "tool_name,tool_status,grant_id,job_id,error_code,created_at_ms,finished_at_ms "
            "FROM agent_turns WHERE conversation_id=? AND actor=? "
            "ORDER BY created_at_ms DESC, turn_id DESC LIMIT ?",
            (conversation_id, actor, limit),
        ).fetchall()
    return [dict(row) for row in reversed(rows)]


def consume_budget(
    db_path: str, *, actor: str, limit: int, window_ms: int, now_ms: int | None = None,
) -> bool:
    """Fixed-window per-actor budget; returns False when exhausted."""
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Invalid budget limit")
    if type(window_ms) is not int or not 60_000 <= window_ms <= 86_400_000:
        raise ValueError("Invalid budget window")
    now = _now_ms() if now_ms is None else now_ms
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT window_start_ms,count FROM agent_budgets WHERE actor=?", (actor,)
        ).fetchone()
        if row is None or now - row["window_start_ms"] >= window_ms:
            conn.execute(
                "INSERT INTO agent_budgets (actor,window_start_ms,count) VALUES (?,?,1) "
                "ON CONFLICT(actor) DO UPDATE SET window_start_ms=excluded.window_start_ms,"
                "count=1",
                (actor, now),
            )
            return True
        if row["count"] >= limit:
            return False
        conn.execute(
            "UPDATE agent_budgets SET count=count+1 WHERE actor=?", (actor,)
        )
        return True


def recover_incomplete_turns(db_path: str, *, actor: str | None = None) -> int:
    """Mark crash-surviving RUNNING turns UNKNOWN. Never re-executes them.

    Called on startup. An interrupted turn may have reached the model provider
    or the kernel operator, so its outcome is genuinely unknown.
    """
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if actor is None:
            changed = conn.execute(
                "UPDATE agent_turns SET status='UNKNOWN',error_code='INTERRUPTED',"
                "finished_at_ms=? WHERE status='RUNNING'", (_now_ms(),),
            ).rowcount
        else:
            changed = conn.execute(
                "UPDATE agent_turns SET status='UNKNOWN',error_code='INTERRUPTED',"
                "finished_at_ms=? WHERE status='RUNNING' AND actor=?", (_now_ms(), actor),
            ).rowcount
    return changed


def conversation_summary(db_path: str, *, actor: str) -> dict[str, Any]:
    """Coarse, owner-scoped counts used by the read-only ``os.queue_summary`` tool."""
    with _connect(db_path) as conn:
        control = conn.execute(
            "SELECT halted,updated_at_ms FROM control WHERE singleton=1"
        ).fetchone()
        jobs = conn.execute(
            "SELECT status,COUNT(*) AS count FROM jobs GROUP BY status"
        ).fetchall()
        turns = conn.execute(
            "SELECT status,COUNT(*) AS count FROM agent_turns WHERE actor=? GROUP BY status",
            (actor,),
        ).fetchall()
    return {
        "dispatch_halted": bool(control["halted"]) if control else True,
        "jobs": {row["status"]: row["count"] for row in jobs},
        "owner_turns": {row["status"]: row["count"] for row in turns},
    }
