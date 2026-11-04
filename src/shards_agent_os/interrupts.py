"""Operator-owned software halt latch. Does NOT interrupt running kernel tools."""
from __future__ import annotations

import time
from pathlib import Path
from .storage import open_db


def control_state(db_path: str | Path) -> dict:
    with open_db(db_path) as conn:
        row = conn.execute("SELECT halted,reason,updated_at_ms FROM control WHERE singleton=1").fetchone()
        return {"halted": bool(row["halted"]), "reason": row["reason"], "updated_at_ms": row["updated_at_ms"]}


def halt(db_path: str | Path, reason: str) -> bool:
    """Block new claims. Existing RUNNING work may continue externally."""
    if type(reason) is not str or not 1 <= len(reason) <= 256:
        raise ValueError("Reason must be 1..256 characters")
    with open_db(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            "UPDATE control SET halted=1,reason=?,updated_at_ms=? WHERE singleton=1 AND halted=0",
            (reason, int(time.time()*1000)),
        ).rowcount
    return bool(changed)


def resume(db_path: str | Path) -> bool:
    """Explicit operator restart of dispatch, not a reset of kernel HALTED."""
    with open_db(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            "UPDATE control SET halted=0,reason='',updated_at_ms=? WHERE singleton=1 AND halted=1",
            (int(time.time()*1000),),
        ).rowcount
    return bool(changed)
