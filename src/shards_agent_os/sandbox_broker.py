"""Linux AF_UNIX broker for a separately privileged, signed sandbox operator.

Unlike an MCP stdio child, this long-lived process can run under its OWN
dedicated host identity. The requesting agent needs only permission to connect
to a group-readable Unix socket. SO_PEERCRED pins the actual connecting UID.
The agent never receives the Docker socket, signing key or operator process UID.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import secrets
import signal
import socket
import stat
import struct
import sys
from pathlib import Path
from typing import Any, Sequence

from shards_kernel.cli.service import exclusive_local_audit_lock
from shards_kernel.integrations.mcp_adapter import MCPAdapter, MCPToolCall
from shards_kernel.integrations.wire import permit_from_mapping

from .governed_sandbox import TOOL_NAME, make_sandbox_handler
from .sandbox_executor import GVisorExecutor
from .sandbox_operator import _secure_database, build_persistent_sandbox_kernel
from .sandbox_recovery import recover_orphans

_MAX_REQUEST = 64 * 1024
_MAX_REPLY = 96 * 1024


class BrokerError(ValueError):
    """Invalid or unauthorised request; no container may be launched."""


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise BrokerError("Duplicate JSON key")
        obj[key] = value
    return obj


def _reject_constant(_value: str) -> None:
    raise BrokerError("Nonfinite numeric input")


def _parse_request(data: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Require one bounded, exactly scoped tool call and a mapped signed permit."""
    if type(data) is not bytes or not data or len(data) > _MAX_REQUEST:
        raise BrokerError("Request size invalid")
    try:
        message = json.loads(
            data.decode("utf-8"), object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise BrokerError("Invalid UTF-8 JSON request") from exc
    if (
        type(message) is not dict
        or set(message) != {"name", "arguments", "permit"}
        or message["name"] != TOOL_NAME
        or type(message["arguments"]) is not dict
        or type(message["permit"]) is not dict
    ):
        raise BrokerError("Expected exact sandbox.exec arguments and signed permit")
    return message["arguments"], message["permit"]


def _read_frame(conn: socket.socket) -> bytes:
    conn.settimeout(4)
    data = bytearray()
    while len(data) <= _MAX_REQUEST:
        chunk = conn.recv(min(4096, _MAX_REQUEST + 1 - len(data)))
        if not chunk:
            raise BrokerError("Incomplete request frame")
        data.extend(chunk)
        if b"\n" in chunk:
            head, rest = bytes(data).split(b"\n", 1)
            if rest.strip():
                raise BrokerError("Multiple or appended requests refused")
            if not head or len(head) > _MAX_REQUEST:
                raise BrokerError("Request frame too large")
            return head
    raise BrokerError("Request exceeds maximum size")


def _peer_uid(conn: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BrokerError("Linux peer credentials unavailable")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def _socket_path(raw: str) -> Path:
    """Reject user-influenced paths and mutable parent directories."""
    if os.geteuid() == 0:
        raise PermissionError("Refusing to run Docker broker as root")
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("Invalid Unix socket path")
    path = Path(raw)
    if not path.is_absolute() or path.name in (".", "..") or len(os.fsencode(path)) > 99:
        raise ValueError("Socket requires a short absolute filesystem path")
    parent = path.parent
    info = parent.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or parent.is_symlink()
        or info.st_uid != os.geteuid()
        or (stat.S_IMODE(info.st_mode) & 0o027) != 0
    ):
        raise PermissionError("Socket directory must be operator-owned, not group/world writable")
    return path


def _remove_stale_socket(path: Path) -> None:
    """Only remove a previous *owned socket* after proving no active listener."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
        raise PermissionError("Refusing to replace foreign or non-socket object")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        try:
            probe.connect(str(path))
        except OSError as exc:
            if exc.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                raise BrokerError("Existing socket could not be inspected") from exc
        else:
            raise BrokerError("Another active broker already owns this socket")
    finally:
        probe.close()
    current = path.lstat()
    if current.st_dev != info.st_dev or current.st_ino != info.st_ino:
        raise BrokerError("Socket identity changed during recovery")
    path.unlink()


def _send(conn: socket.socket, payload: dict[str, Any]) -> None:
    try:
        encoded = json.dumps(
            payload, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
    except (ValueError, TypeError):
        encoded = b'{"decision":"UNKNOWN","error":"Result encoding failed"}\n'
    if len(encoded) > _MAX_REPLY:
        encoded = b'{"decision":"UNKNOWN","error":"Result exceeds response limit"}\n'
    conn.sendall(encoded)


def _handle(conn: socket.socket, *, peer_uid: int, adapter: MCPAdapter) -> None:
    """Authenticate Linux peer before reading untrusted request bytes."""
    try:
        if _peer_uid(conn) != peer_uid:
            _send(conn, {"decision": "DENY", "error": "Unauthorised OS peer"})
            return
        args, mapping = _parse_request(_read_frame(conn))
        permit = permit_from_mapping(mapping)
    except (BrokerError, OSError, ValueError, KeyError, TypeError):
        _send(conn, {"decision": "DENY", "error": "Invalid or unauthorised request"})
        return
    try:
        receipt = adapter.handle_tool_call(
            MCPToolCall(
                id="sandbox-broker-" + secrets.token_hex(16),
                name=TOOL_NAME, arguments=args,
            ),
            permit_token=permit,
        )
        if receipt.is_error:
            _send(conn, {"decision": "DENY", "error": "Kernel denied operation"})
        else:
            _send(conn, {
                "decision": "ALLOW", "result": receipt.content,
            })
    except Exception:
        # A caller must never infer that an attempted effect did not happen
        # simply because its RPC session failed. No retry is ever initiated.
        _send(conn, {"decision": "UNKNOWN", "error": "Execution outcome uncertain"})


def serve_unix(
    *, socket_path: str, peer_uid: int, kernel_id: str, actor: str,
    audit_db: str, issuer: str, key_id: str, public_key_hex: str,
) -> None:
    """Serve one request per connection under a distinct trusted Linux UID."""
    if type(peer_uid) is not int or peer_uid <= 0 or peer_uid == os.geteuid():
        raise ValueError("An independent nonroot agent UID is required")
    path = _socket_path(socket_path)
    db = _secure_database(audit_db)
    with exclusive_local_audit_lock(db):
        kernel = build_persistent_sandbox_kernel(
            kernel_id=kernel_id, actor=actor, audit_db=str(db),
            issuer=issuer, key_id=key_id, public_key_hex=public_key_hex,
        )
        executor = GVisorExecutor(owner_id=kernel_id)
        recover_orphans(executor, audit_db=db, owner_id=kernel_id)
        adapter = MCPAdapter(kernel, actor=actor)
        adapter.register_tool(TOOL_NAME, make_sandbox_handler(executor))
        _remove_stale_socket(path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            old_umask = os.umask(0o077)
            try:
                listener.bind(str(path))
            finally:
                os.umask(old_umask)
            info = path.lstat()
            try:
                # Group permission is deliberate: the broker's host service
                # group grants *connect only*, never Docker/audit access.
                os.chmod(path, 0o660)
                listener.listen(8)
                listener.settimeout(0.5)
                stop = False

                def stop_service(_signum: int, _frame: Any) -> None:
                    nonlocal stop
                    stop = True

                previous_term = signal.signal(signal.SIGTERM, stop_service)
                previous_int = signal.signal(signal.SIGINT, stop_service)
                try:
                    while not stop:
                        try:
                            conn, _ = listener.accept()
                        except socket.timeout:
                            continue
                        with conn:
                            try:
                                _handle(conn, peer_uid=peer_uid, adapter=adapter)
                            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                                # The permit may already be consumed; never retry.
                                pass
                finally:
                    signal.signal(signal.SIGTERM, previous_term)
                    signal.signal(signal.SIGINT, previous_int)
            finally:
                try:
                    current = path.lstat()
                    if current.st_dev == info.st_dev and current.st_ino == info.st_ino:
                        path.unlink()
                except FileNotFoundError:
                    pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shards-agent-os-broker",
        description="Host-isolated, SO_PEERCRED-authenticated Unix sandbox broker",
    )
    parser.add_argument("--socket", required=True)
    parser.add_argument("--peer-uid", required=True, type=int)
    parser.add_argument("--kernel-id", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--audit-db", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--public-key-hex", required=True)
    args = parser.parse_args(argv)
    try:
        serve_unix(
            socket_path=args.socket, peer_uid=args.peer_uid,
            kernel_id=args.kernel_id, actor=args.actor,
            audit_db=args.audit_db, issuer=args.issuer,
            key_id=args.key_id, public_key_hex=args.public_key_hex,
        )
    except KeyboardInterrupt:
        return 0
    except Exception:
        print("Sandbox broker startup failed; check trusted host diagnostics", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
