"""Offline, human-controlled Ed25519 issuer for one sandbox.exec workload.

Run on an independently trusted approval workstation, NEVER from an agent or
the Docker-authorised sandbox host. This CLI is intentionally not an MCP tool.
The encrypted private key is never printed, sent to the sandbox, or placed in the permit.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import stat
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.permits import PermitBuilder

from .sandbox_client import _private_json
from .sandbox_executor import ExecutionSpec

_FIELDS = frozenset({
    "image", "argv", "timeout_seconds", "memory_megabytes",
    "cpu_millicores", "pids_limit",
})
_IDENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_KEY_BYTES = 4096
_MIN_PASSPHRASE_BYTES = 16


def _key_passphrase(*, confirm: bool) -> bytes:
    """Read only from a live approver terminal, never argv/env/agent transport."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise PermissionError("Offline signing requires an interactive terminal")
    value = getpass.getpass("Offline signing-key passphrase: ").encode("utf-8")
    if not _MIN_PASSPHRASE_BYTES <= len(value) <= 1024:
        raise ValueError("Offline signer requires a strong passphrase")
    if confirm:
        repeated = getpass.getpass("Confirm signing-key passphrase: ").encode("utf-8")
        if value != repeated:
            raise ValueError("Passphrase confirmation failed")
    return value


def _valid_passphrase(value: bytes) -> bytes:
    if type(value) is not bytes or not _MIN_PASSPHRASE_BYTES <= len(value) <= 1024:
        raise ValueError("Offline signer requires a strong passphrase")
    return value



def _secure_parent(path: Path) -> None:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise ValueError("Approver paths must be absolute")
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o022):
        raise PermissionError("Approver output directory is not trusted")


def _new_file(path: str, data: bytes, *, mode: int) -> None:
    destination = Path(path)
    _secure_parent(destination)
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _load_key(path: str, *, passphrase: bytes) -> Ed25519PrivateKey:
    source = Path(path)
    _secure_parent(source)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 1 <= info.st_size <= _MAX_KEY_BYTES):
            raise PermissionError("Private signer key must be an owned 0600 regular file")
        data = os.read(fd, _MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > _MAX_KEY_BYTES:
        raise ValueError("Private signing key exceeds length limit")
    if not data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        raise PermissionError("Unencrypted legacy signing keys are refused")
    key = serialization.load_pem_private_key(data, password=_valid_passphrase(passphrase))
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 signing private key")
    return key


def _request(path: str) -> tuple[dict[str, Any], str]:
    raw = _private_json(path)
    if set(raw) != _FIELDS:
        raise ValueError("The approval request must specify all six exact execution fields")
    if type(raw["argv"]) is not list:
        raise ValueError("The approval request argv must be a JSON list")
    spec = ExecutionSpec(
        image=raw["image"], argv=tuple(raw["argv"]),
        timeout_seconds=raw["timeout_seconds"],
        memory_megabytes=raw["memory_megabytes"],
        cpu_millicores=raw["cpu_millicores"],
        pids_limit=raw["pids_limit"],
    )
    encoded = asdict(spec)
    encoded["argv"] = list(spec.argv)
    # The exact same JSON fields reach the broker and kernel permit scope.
    canonical = json.dumps(encoded, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("ascii")
    digest = hashlib.sha256(canonical).hexdigest()
    if digest != spec.fingerprint():
        raise RuntimeError("Execution fingerprint does not match approved parameters")
    return encoded, digest


def _identifier(value: str, name: str) -> str:
    if type(value) is not str or not _IDENT.fullmatch(value):
        raise ValueError(f"Invalid {name} identifier")
    return value


def issue_permit(
    *, private_key_path: str, request_path: str, output_path: str,
    approval_digest: str, issuer: str, key_id: str, kernel_id: str,
    actor: str, ttl_seconds: int, passphrase: bytes, now_ms: int | None = None,
) -> dict[str, Any]:
    """Issue one signed permit only for an externally approved exact digest."""
    issuer = _identifier(issuer, "issuer")
    key_id = _identifier(key_id, "key ID")
    kernel_id = _identifier(kernel_id, "kernel")
    actor = _identifier(actor, "actor")
    if (type(ttl_seconds) is not int or not 10 <= ttl_seconds <= 300
        or type(approval_digest) is not str
        or not _DIGEST.fullmatch(approval_digest)):
        raise ValueError("Explicit SHA-256 approval and a 10–300 s TTL required")
    payload, computed = _request(request_path)
    if computed != approval_digest:
        raise PermissionError("Approved digest differs from exact execution request")
    key = _load_key(private_key_path, passphrase=passphrase)
    issued = int(time.time() * 1000) if now_ms is None else now_ms
    if type(issued) is not int or issued <= 30000:
        raise ValueError("Invalid issuer UTC timestamp")
    valid_from = issued - 30000
    until = issued + ttl_seconds * 1000
    unsigned = (
        PermitBuilder()
        .issuer(issuer)
        .subject(actor)
        .jurisdiction("default")
        .action("sandbox.exec")
        .params(payload)
        .max_executions(1)
        .valid_from_ms(valid_from)
        .valid_until_ms(until)
        .proposal_hash("sha256:" + computed)
        .build_unsigned_v2(key_id=key_id, audience=kernel_id)
    )
    signed = sign_v2_permit(unsigned, key)
    wire = permit_to_mapping(signed)
    data = json.dumps(wire, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii") + b"\n"
    _new_file(output_path, data, mode=0o600)
    return {
        "permit_id": signed.permit_id,
        "approval_digest": computed,
        "valid_until_ms": until,
        "max_executions": 1,
        "output_created": True,
    }


def generate_key(*, private_path: str, public_path: str, passphrase: bytes) -> dict[str, Any]:
    if Path(private_path) == Path(public_path):
        raise ValueError("Private and public key paths must differ")
    _secure_parent(Path(private_path))
    _secure_parent(Path(public_path))
    if Path(private_path).exists() or Path(public_path).exists():
        raise FileExistsError("Refusing to overwrite an existing signer")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(_valid_passphrase(passphrase)),
    )
    public = key.public_key().public_bytes_raw().hex()
    _new_file(private_path, pem, mode=0o600)
    # The public verifier is not secret and can be transferred to a trusted
    # administrator. It is deliberately not a backup of the private signer.
    _new_file(public_path, (public + "\n").encode("ascii"), mode=0o644)
    return {"public_key_hex": public, "private_key_created": True}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shards-agent-os-approve",
        description="OFFLINE signed sandbox permit issuer; never run inside agent or sandbox host",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    key = actions.add_parser("keygen", help="Create independent Ed25519 signing identity")
    key.add_argument("--private-key-file", required=True)
    key.add_argument("--public-key-file", required=True)
    digest = actions.add_parser("digest", help="Inspect exact workload SHA-256 for human approval")
    digest.add_argument("--arguments-file", required=True)
    issue = actions.add_parser("issue", help="Issue one-use permit after verifying exact digest")
    issue.add_argument("--private-key-file", required=True)
    issue.add_argument("--arguments-file", required=True)
    issue.add_argument("--permit-file", required=True)
    issue.add_argument("--approve-sha256", required=True)
    issue.add_argument("--issuer", required=True)
    issue.add_argument("--key-id", required=True)
    issue.add_argument("--kernel-id", required=True)
    issue.add_argument("--actor", required=True)
    issue.add_argument("--ttl-seconds", type=int, default=120)
    args = parser.parse_args(argv)
    try:
        if args.action == "keygen":
            result = generate_key(
                private_path=args.private_key_file, public_path=args.public_key_file,
                passphrase=_key_passphrase(confirm=True),
            )
        elif args.action == "digest":
            request, sha = _request(args.arguments_file)
            result = {"approval_digest": sha, "request": request}
        else:
            result = issue_permit(
                private_key_path=args.private_key_file,
                request_path=args.arguments_file, output_path=args.permit_file,
                approval_digest=args.approve_sha256,
                issuer=args.issuer, key_id=args.key_id, kernel_id=args.kernel_id,
                actor=args.actor, ttl_seconds=args.ttl_seconds,
                passphrase=_key_passphrase(confirm=False),
            )
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    except Exception:
        print(
            '{"ok":false,"error":"Offline approval refused; verify issuer identity, '
            'exact request digest and private file permissions"}',
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
