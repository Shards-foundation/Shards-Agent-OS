"""Unprivileged sandbox broker client: no Docker, issuer or host API credentials."""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

_MAX_REQUEST = 64 * 1024
_MAX_REPLY = 96 * 1024


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("Non-finite JSON constant")


def _private_json(path: str) -> dict[str, Any]:
    if type(path) is not str or not Path(path).is_absolute():
        raise ValueError("Only absolute private JSON paths are allowed")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _MAX_REQUEST
        ):
            raise PermissionError("Input file must be a private regular 0600 file")
        data = os.read(fd, _MAX_REQUEST + 1)
    finally:
        os.close(fd)
    if not data or len(data) > _MAX_REQUEST:
        raise ValueError("Invalid input file size")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_constant=_reject_constant)
    if type(value) is not dict:
        raise ValueError("Input file must be a JSON object")
    return value


def call_broker(
    *, socket_path: str, expected_operator_uid: int,
    arguments: dict[str, Any], permit: dict[str, Any],
    timeout_s: float = 150.0,
) -> dict[str, Any]:
    """Submit one signed call over AF_UNIX; never retries on ambiguous failure."""
    if (
        type(socket_path) is not str or not Path(socket_path).is_absolute()
        or type(expected_operator_uid) is not int
        or expected_operator_uid < 1
        or expected_operator_uid == os.geteuid()
    ):
        raise ValueError("A distinct trusted operator UID and absolute socket are required")
    if type(timeout_s) not in (int, float) or not 1 <= timeout_s <= 180:
        raise ValueError("Broker wait must be between 1 and 180 seconds")
    info = os.lstat(socket_path)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != expected_operator_uid:
        raise PermissionError("Socket does not belong to the pinned operator")
    payload = json.dumps(
        {"name": "sandbox.exec", "arguments": arguments, "permit": permit},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8") + b"\n"
    if len(payload) > _MAX_REQUEST:
        raise ValueError("Signed request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        # Workloads can run for 120 s plus verified daemon setup/cleanup.
        # An RPC timeout is UNKNOWN, never a safe reason to retry.
        client.settimeout(timeout_s)
        client.connect(socket_path)
        client.sendall(payload)
        data = bytearray()
        while len(data) <= _MAX_REPLY:
            block = client.recv(min(4096, _MAX_REPLY + 1 - len(data)))
            if not block:
                raise ConnectionError("Broker closed without a result")
            data.extend(block)
            if b"\n" in block:
                message, rest = bytes(data).split(b"\n", 1)
                if rest.strip():
                    raise ValueError("Broker emitted multiple frames")
                result = json.loads(message, object_pairs_hook=_pairs,
                                    parse_constant=_reject_constant)
                if type(result) is not dict or result.get("decision") not in (
                    "ALLOW", "DENY", "UNKNOWN"
                ):
                    raise ValueError("Unrecognised broker decision")
                return result
    raise ValueError("Broker response exceeds permitted size")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shards-agent-os-sandbox-call",
        description="Make one signed call to a separately privileged local broker",
    )
    parser.add_argument("--socket", required=True)
    parser.add_argument("--operator-uid", type=int, required=True)
    parser.add_argument("--arguments-file", required=True)
    parser.add_argument("--permit-file", required=True)
    args = parser.parse_args(argv)
    try:
        result = call_broker(
            socket_path=args.socket,
            expected_operator_uid=args.operator_uid,
            arguments=_private_json(args.arguments_file),
            permit=_private_json(args.permit_file),
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":"),
                         allow_nan=False))
        if result["decision"] == "ALLOW" and (
            type(result.get("result")) is dict
            and result["result"].get("status") == "EXITED"
            and result["result"].get("exit_code") == 0
            and result["result"].get("cleanup_confirmed") is True
        ):
            return 0
        if result["decision"] == "DENY":
            return 2
        return 3
    except Exception:
        # A network or decoding failure is UNKNOWN, not proof of denial.
        print('{"decision":"UNKNOWN","error":"Local broker call failed"}')
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
