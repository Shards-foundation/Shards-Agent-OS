"""Fail-closed recovery of gVisor containers left by a crashed trusted operator.

The trusted operator alone owns one pinned identity and a single-writer audit
lock. Workloads are *never* resumed or reissued. Recovery only terminates
containers carrying that operator's explicit immutable Docker labels.
"""
from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from .sandbox_executor import GVisorExecutor, SandboxUnavailable

_CONTAINER = re.compile(r"shards-sbx-[0-9a-f]{32}\Z")
_MAX_LIST_BYTES = 65536
_MAX_ORPHANS = 128
_TIMEOUT = 15
_TABLE = """CREATE TABLE IF NOT EXISTS sandbox_orphan_recovery (
    container_name TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    completed_ms INTEGER,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('STARTED', 'REMOVED', 'ABSENT')
    )
)"""


def _docker(
    executor: GVisorExecutor, args: list[str], env: dict[str, str],
    *, timeout: int = _TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            executor._base() + args,
            capture_output=True, text=True, timeout=timeout,
            check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxUnavailable("Container lifecycle inspection unavailable") from exc
    if len(result.stdout.encode("utf-8")) > _MAX_LIST_BYTES or len(
        result.stderr.encode("utf-8")
    ) > _MAX_LIST_BYTES:
        raise SandboxUnavailable("Oversized container lifecycle response")
    return result


def _inspect_owner(
    executor: GVisorExecutor, name: str, owner_id: str, env: dict[str, str],
) -> bool:
    """True when matching owned container exists, False when proven absent."""
    result = _docker(
        executor, ["container", "inspect", "--format", "{{json .Config.Labels}}", name],
        env,
    )
    if result.returncode != 0:
        if "No such container" in result.stderr:
            return False
        raise SandboxUnavailable("Container ownership inspection uncertain")
    try:
        labels = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise SandboxUnavailable("Unparseable container ownership labels") from exc
    if (
        type(labels) is not dict
        or labels.get("shards.agent-os.owner") != owner_id
        or labels.get("shards.agent-os.sandbox") != "1"
    ):
        raise SandboxUnavailable("Refusing to remove a container without exact ownership")
    return True


def _recover_one(
    executor: GVisorExecutor, name: str, owner_id: str, env: dict[str, str],
) -> str:
    if not _inspect_owner(executor, name, owner_id, env):
        return "ABSENT"
    # Docker socket is accessible *only* from the trusted operator process.
    # No agent-controlled IDs, Docker arguments or selectors reach this call.
    _docker(executor, ["container", "rm", "--force", "--volumes", name], env)
    if _inspect_owner(executor, name, owner_id, env):
        raise SandboxUnavailable("Orphan container remains after forced removal")
    return "REMOVED"


def recover_orphans(
    executor: GVisorExecutor, *, audit_db: str | Path, owner_id: str,
) -> list[str]:
    """Recover after acquiring the same operator's exclusive audit DB lock.

    A STARTED journal record is committed *before* any Docker mutation.
    On crash, the next startup repeats the ownership check and confirms
    absence/removal. A daemon failure or suspicious label blocks startup.
    No workload is ever resumed or replayed. Do not call while the owner's
    previous instance is still serving requests.
    """
    if type(executor) is not GVisorExecutor or executor.owner_id != owner_id:
        raise ValueError("Orphan recovery requires an exact, owner-bound executor")
    if type(owner_id) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", owner_id):
        raise ValueError("Invalid immutable operator identity")
    with tempfile.TemporaryDirectory(prefix="shards-recovery-config-") as config:
        env = {"PATH": "/usr/bin:/bin", "HOME": config,
               "DOCKER_CONFIG": config, "LC_ALL": "C"}
        executor._preflight(env)
        listed = _docker(
            executor,
            [
                "container", "ls", "--all",
                "--filter", "label=shards.agent-os.sandbox=1",
                "--filter", f"label=shards.agent-os.owner={owner_id}",
                "--format", "{{.Names}}",
            ],
            env,
        )
        if listed.returncode != 0:
            raise SandboxUnavailable("Cannot enumerate owned sandbox containers")
        names = [line.strip() for line in listed.stdout.splitlines()]
        if len(names) > _MAX_ORPHANS or any(not _CONTAINER.fullmatch(x) for x in names):
            raise SandboxUnavailable("Untrusted or oversized orphan container listing")
        try:
            with sqlite3.connect(str(audit_db), timeout=3) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute(_TABLE)
                pending = db.execute(
                    "SELECT container_name FROM sandbox_orphan_recovery "
                    "WHERE operator_id=? AND outcome='STARTED'", (owner_id,),
                ).fetchall()
                targets = sorted(set(names) | {row[0] for row in pending})
                if len(targets) > _MAX_ORPHANS or any(
                    not _CONTAINER.fullmatch(x) for x in targets
                ):
                    raise SandboxUnavailable("Recovery journal contains invalid containers")
                done: list[str] = []
                for name in targets:
                    with db:
                        db.execute(
                            "INSERT OR IGNORE INTO sandbox_orphan_recovery "
                            "(container_name, operator_id, first_seen_ms, outcome) "
                            "VALUES (?, ?, ?, 'STARTED')",
                            (name, owner_id, time.time_ns() // 1_000_000),
                        )
                    # An existing completed record with the same name is
                    # never silently reused; container names are random 128-bit.
                    row = db.execute(
                        "SELECT operator_id, outcome FROM sandbox_orphan_recovery "
                        "WHERE container_name=?", (name,),
                    ).fetchone()
                    if row != (owner_id, "STARTED"):
                        raise SandboxUnavailable("Container recovery journal identity conflict")
                    outcome = _recover_one(executor, name, owner_id, env)
                    with db:
                        db.execute(
                            "UPDATE sandbox_orphan_recovery SET completed_ms=?, outcome=? "
                            "WHERE container_name=? AND operator_id=? AND outcome='STARTED'",
                            (time.time_ns() // 1_000_000, outcome, name, owner_id),
                        )
                    done.append(name)
                return done
        except sqlite3.Error as exc:
            raise SandboxUnavailable("Durable orphan recovery journal unavailable") from exc
