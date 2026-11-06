"""Trusted, Linux-only, persistent stdio operator for sandbox.exec.

The process must be launched as a separately supervised, Docker-authorised
service identity. Agent-controlled execution of this entrypoint under that same
identity is NOT a security boundary. No signing private keys or agent bearers
are accepted by this process.
"""
from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path
from typing import Sequence

from implementations.storage import SQLiteAuditStorage
from shards_kernel.api import KernelConfig, StrictKernel
from shards_kernel.cli.service import exclusive_local_audit_lock
from shards_kernel.common.time import PersistentSystemClock
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.permits import PublicVerificationKey

from .governed_sandbox import create_governed_sandbox_server
from .sandbox_executor import GVisorExecutor
from .sandbox_recovery import recover_orphans

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
PUBLIC_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _identifier(value: str, *, label: str) -> str:
    if type(value) is not str or not IDENTIFIER.fullmatch(value) or value in (".", ".."):
        raise ValueError(f"Invalid {label}")
    return value


def _secure_database(path: str) -> Path:
    """Create or verify one private audit database in an owned 0700 directory.

    This precondition prevents accidental world-readable local audit state.
    It is not a defence against a hostile administrator/root user.
    """
    if sys.platform != "linux":
        raise OSError("Sandbox operator only supports Linux")
    if type(path) is not str or not path or "\x00" in path:
        raise ValueError("Invalid database path")
    db = Path(path)
    if not db.is_absolute() or db.name in (".", ".."):
        raise ValueError("Audit database path must be absolute")
    parent = db.parent
    pst = parent.lstat()
    if (not stat.S_ISDIR(pst.st_mode) or parent.is_symlink()
            or pst.st_uid != os.geteuid() or pst.st_mode & 0o077):
        raise PermissionError("Audit database parent must be an owned 0700 directory")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(db, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise PermissionError("Audit database must be a private owned regular file")
        if os.stat(db, follow_symlinks=False).st_ino != st.st_ino:
            raise OSError("Audit database inode changed")
    finally:
        os.close(fd)
    return db


def build_persistent_sandbox_kernel(
    *, kernel_id: str, actor: str, audit_db: str,
    issuer: str, key_id: str, public_key_hex: str,
) -> StrictKernel:
    """Restore audit and replay state with a persistent wall-clock high-water mark.

    Only this kernel's exact actor and sandbox.exec action are allowed.
    The issuer's Ed25519 private key must reside outside the operator.
    """
    kernel_id = _identifier(kernel_id, label="kernel ID")
    actor = _identifier(actor, label="actor")
    issuer = _identifier(issuer, label="issuer")
    key_id = _identifier(key_id, label="key ID")
    if type(public_key_hex) is not str or not PUBLIC_HEX.fullmatch(public_key_hex):
        raise ValueError("Pinned verifier requires 64 lowercase Ed25519 hex digits")
    db = _secure_database(audit_db)
    storage = SQLiteAuditStorage(str(db))
    kernel = StrictKernel(audit_storage=storage)
    kernel.boot(
        KernelConfig(
            kernel_id=kernel_id,
            variant="strict",
            clock=PersistentSystemClock(str(db), kernel_id),
        )
    )
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({actor}),
            allowed_tools=frozenset({"sandbox.exec"}),
        )
    )
    kernel.set_public_verifiers({
        key_id: PublicVerificationKey(
            issuer=issuer,
            audience=kernel_id,
            public_key=bytes.fromhex(public_key_hex),
        )
    })
    return kernel


def serve_stdio(
    *, kernel_id: str, actor: str, audit_db: str,
    issuer: str, key_id: str, public_key_hex: str,
) -> None:
    """Hold the single-writer audit lock for the lifetime of the MCP server."""
    # Validate first, then lock the privately owned audit state before boot.
    db = _secure_database(audit_db)
    with exclusive_local_audit_lock(db):
        kernel = build_persistent_sandbox_kernel(
            kernel_id=kernel_id, actor=actor, audit_db=str(db),
            issuer=issuer, key_id=key_id, public_key_hex=public_key_hex,
        )
        # After acquiring the single-writer lock, terminate only this
        # operator's labelled orphan containers. Any uncertain removal
        # refuses startup; already consumed permits are never replayed.
        executor = GVisorExecutor(owner_id=kernel_id)
        recover_orphans(executor, audit_db=db, owner_id=kernel_id)
        server = create_governed_sandbox_server(
            kernel, actor=actor, executor=executor,
        )
        # Stdout belongs entirely to the official MCP transport.
        server.run(transport="stdio")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shards-agent-os-sandbox",
        description="Trusted local-only signed sandbox MCP operator (Linux)",
    )
    parser.add_argument("--kernel-id", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--audit-db", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--public-key-hex", required=True)
    args = parser.parse_args(argv)
    try:
        serve_stdio(
            kernel_id=args.kernel_id, actor=args.actor,
            audit_db=args.audit_db, issuer=args.issuer,
            key_id=args.key_id, public_key_hex=args.public_key_hex,
        )
    except KeyboardInterrupt:
        return 0
    except Exception:
        print(
            "Sandbox operator refused startup or failed; check trusted host diagnostics",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
