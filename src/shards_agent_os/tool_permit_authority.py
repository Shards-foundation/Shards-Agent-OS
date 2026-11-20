"""Independent tool authority: the only component that can authorise a tool call.

Two artefacts are produced here, and neither can be produced by the Agent OS:

``delegation``
    A signed, audience-bound, expiring statement that a named actor may use a
    named set of *read-only observation* tools for at most N executions. It
    replaces the idea of "the OS decides who may look at the queue" with an
    external decision the OS can only verify.

``kernel permit bundle``
    A Shards-Kernel v2 Ed25519 permit for one exact ``echo``/``add`` call,
    plus a signed sidecar describing the actor, tool and canonical argument
    digest. The Agent OS holds only the authority's *public* key and the
    kernel operator's *public* key; it can verify both and mint neither.

Run this on a separately trusted approval workstation, never on the host that
serves the web UI. The private key is passphrase-encrypted and read from an
owned 0600 file through a live terminal, exactly like the existing offline
sandbox approver.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any

GRANT_DOMAIN = b"shards-agent-os/tool-delegation/v1\x00"
BUNDLE_DOMAIN = b"shards-agent-os/kernel-permit-bundle/v1\x00"
OBSERVATION_TOOLS = ("os.queue_summary", "os.halt_state")
KERNEL_TOOLS = ("kernel.echo", "kernel.add")

_IDENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
# Actors are edge identities, which are usually e-mail addresses.
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,253}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_KEY_BYTES = 4096
_MIN_PASSPHRASE = 16


class AuthorityError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def arguments_digest(tool: str, arguments: dict) -> str:
    """Stable digest binding a tool name to its exact canonical arguments."""
    return hashlib.sha256(
        _canonical({"tool": tool, "arguments": arguments})
    ).hexdigest()


def _public_verifier(public_key_hex: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if type(public_key_hex) is not str or not re.fullmatch(r"[0-9a-f]{64}", public_key_hex):
        raise AuthorityError("INVALID_PUBLIC_KEY")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))


def verify_signed(document: dict, *, public_key_hex: str, domain: bytes) -> dict:
    """Verify a signed document and return its unsigned payload.

    The domain prefix prevents a signature over one document type being
    replayed as another.
    """
    if type(document) is not dict:
        raise AuthorityError("MALFORMED_DOCUMENT")
    signature = document.get("signature")
    if type(signature) is not str or not re.fullmatch(r"[0-9a-f]{128}", signature):
        raise AuthorityError("MALFORMED_SIGNATURE")
    payload = {key: value for key, value in document.items() if key != "signature"}
    key = _public_verifier(public_key_hex)
    try:
        key.verify(bytes.fromhex(signature), domain + _canonical(payload))
    except Exception:
        raise AuthorityError("SIGNATURE_INVALID") from None
    return payload


def _check_window(payload: dict, now_ms: int, *, max_ttl_ms: int) -> None:
    start, until = payload.get("valid_from_ms"), payload.get("valid_until_ms")
    if type(start) is not int or type(until) is not int or until <= start:
        raise AuthorityError("INVALID_VALIDITY_WINDOW")
    if until - start > max_ttl_ms:
        raise AuthorityError("VALIDITY_WINDOW_TOO_LONG")
    if now_ms < start - 30_000 or now_ms >= until:
        raise AuthorityError("AUTHORITY_EXPIRED")


def verify_delegation(
    document: dict, *, public_key_hex: str, audience: str, actor: str,
    now_ms: int | None = None,
) -> dict:
    """Verify an observation delegation for this instance, actor and moment."""
    payload = verify_signed(document, public_key_hex=public_key_hex, domain=GRANT_DOMAIN)
    if payload.get("v") != 1 or payload.get("kind") != "observation-delegation":
        raise AuthorityError("WRONG_DOCUMENT_KIND")
    if payload.get("audience") != audience:
        raise AuthorityError("AUDIENCE_MISMATCH")
    if type(actor) is not str or not _ACTOR.fullmatch(actor):
        raise AuthorityError("INVALID_ACTOR")
    if payload.get("actor") != actor:
        raise AuthorityError("ACTOR_MISMATCH")
    tools = payload.get("tools")
    if (type(tools) is not list or not tools
            or any(t not in OBSERVATION_TOOLS for t in tools)
            or len(set(tools)) != len(tools)):
        raise AuthorityError("INVALID_TOOL_SCOPE")
    uses = payload.get("max_executions")
    if type(uses) is not int or not 1 <= uses <= 10_000:
        raise AuthorityError("INVALID_EXECUTION_BUDGET")
    if type(payload.get("delegation_id")) is not str or not re.fullmatch(
        r"[0-9a-f]{32}", payload["delegation_id"]
    ):
        raise AuthorityError("INVALID_DELEGATION_ID")
    _check_window(payload, int(time.time() * 1000) if now_ms is None else now_ms,
                  max_ttl_ms=90 * 24 * 3600 * 1000)
    return payload


def verify_kernel_bundle(
    document: dict, *, public_key_hex: str, audience: str, actor: str,
    tool: str, arguments: dict, now_ms: int | None = None,
) -> dict:
    """Verify a kernel permit bundle binds *this* actor, tool and arguments."""
    payload = verify_signed(document, public_key_hex=public_key_hex, domain=BUNDLE_DOMAIN)
    if payload.get("v") != 1 or payload.get("kind") != "kernel-permit-bundle":
        raise AuthorityError("WRONG_DOCUMENT_KIND")
    if payload.get("audience") != audience:
        raise AuthorityError("AUDIENCE_MISMATCH")
    if type(actor) is not str or not _ACTOR.fullmatch(actor):
        raise AuthorityError("INVALID_ACTOR")
    if payload.get("actor") != actor:
        raise AuthorityError("ACTOR_MISMATCH")
    if payload.get("tool") != tool:
        raise AuthorityError("TOOL_MISMATCH")
    if tool not in KERNEL_TOOLS:
        raise AuthorityError("TOOL_NOT_ALLOWLISTED")
    expected = arguments_digest(tool, arguments)
    if payload.get("arguments_sha256") != expected:
        raise AuthorityError("ARGUMENTS_MISMATCH")
    if payload.get("max_executions") != 1:
        raise AuthorityError("PERMIT_MUST_BE_SINGLE_USE")
    if type(payload.get("permit_file")) is not str or not os.path.isabs(payload["permit_file"]):
        raise AuthorityError("INVALID_PERMIT_PATH")
    if type(payload.get("bundle_id")) is not str or not re.fullmatch(
        r"[0-9a-f]{32}", payload["bundle_id"]
    ):
        raise AuthorityError("INVALID_BUNDLE_ID")
    _check_window(payload, int(time.time() * 1000) if now_ms is None else now_ms,
                  max_ttl_ms=3600 * 1000)
    return payload


# --- Issuance (trusted workstation only) -----------------------------------


def _load_private_key(path: str, passphrase: bytes):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if type(passphrase) is not bytes or not _MIN_PASSPHRASE <= len(passphrase) <= 1024:
        raise AuthorityError("WEAK_PASSPHRASE")
    source = Path(path)
    if not source.is_absolute():
        raise AuthorityError("ABSOLUTE_PATH_REQUIRED")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= _MAX_KEY_BYTES):
            raise AuthorityError("PRIVATE_KEY_PERMISSIONS")
        data = os.read(fd, _MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if not data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        raise AuthorityError("UNENCRYPTED_KEY_REFUSED")
    key = serialization.load_pem_private_key(data, password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise AuthorityError("WRONG_KEY_TYPE")
    return key


def _write_private_json(path: str, payload: dict) -> None:
    target = Path(path)
    if not target.is_absolute() or target.name in ("", ".", ".."):
        raise AuthorityError("ABSOLUTE_PATH_REQUIRED")
    parent = target.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise AuthorityError("UNTRUSTED_OUTPUT_DIRECTORY")
    data = _canonical(payload) + b"\n"
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def generate_authority_key(*, private_path: str, public_path: str, passphrase: bytes) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if type(passphrase) is not bytes or not _MIN_PASSPHRASE <= len(passphrase) <= 1024:
        raise AuthorityError("WEAK_PASSPHRASE")
    if Path(private_path) == Path(public_path):
        raise AuthorityError("DISTINCT_PATHS_REQUIRED")
    if Path(private_path).exists() or Path(public_path).exists():
        raise FileExistsError("Refusing to overwrite an existing authority key")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    _write_private_bytes(private_path, pem, mode=0o600)
    public_hex = key.public_key().public_bytes_raw().hex()
    _write_private_bytes(public_path, (public_hex + "\n").encode("ascii"), mode=0o644)
    return {"public_key_hex": public_hex, "private_key_created": True}


def _write_private_bytes(path: str, data: bytes, *, mode: int) -> None:
    target = Path(path)
    if not target.is_absolute() or target.name in ("", ".", ".."):
        raise AuthorityError("ABSOLUTE_PATH_REQUIRED")
    parent = target.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise AuthorityError("UNTRUSTED_OUTPUT_DIRECTORY")
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def issue_delegation(
    *, private_key_path: str, passphrase: bytes, output_path: str,
    audience: str, actor: str, tools: list[str], max_executions: int,
    ttl_seconds: int, now_ms: int | None = None,
) -> dict:
    if type(audience) is not str or not _IDENT.fullmatch(audience):
        raise AuthorityError("INVALID_AUDIENCE")
    if type(actor) is not str or not _ACTOR.fullmatch(actor):
        raise AuthorityError("INVALID_ACTOR")
    if (type(tools) is not list or not tools or len(set(tools)) != len(tools)
            or any(t not in OBSERVATION_TOOLS for t in tools)):
        raise AuthorityError("INVALID_TOOL_SCOPE")
    if type(max_executions) is not int or not 1 <= max_executions <= 10_000:
        raise AuthorityError("INVALID_EXECUTION_BUDGET")
    if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 90 * 24 * 3600:
        raise AuthorityError("INVALID_TTL")
    issued = int(time.time() * 1000) if now_ms is None else now_ms
    payload = {
        "v": 1, "kind": "observation-delegation",
        "delegation_id": secrets.token_hex(16),
        "audience": audience, "actor": actor, "tools": list(tools),
        "max_executions": max_executions,
        "valid_from_ms": issued,
        "valid_until_ms": issued + ttl_seconds * 1000,
        "issued_at_ms": issued,
    }
    key = _load_private_key(private_key_path, passphrase)
    signature = key.sign(GRANT_DOMAIN + _canonical(payload)).hex()
    document = {**payload, "signature": signature}
    _write_private_json(output_path, document)
    return {"delegation_id": payload["delegation_id"], "output_created": True,
            "valid_until_ms": payload["valid_until_ms"], "max_executions": max_executions}


def issue_kernel_bundle(
    *, private_key_path: str, passphrase: bytes, output_path: str,
    permit_file: str, audience: str, actor: str, tool: str, arguments: dict,
    ttl_seconds: int, now_ms: int | None = None,
) -> dict:
    """Bind an already-signed kernel permit to this actor, tool and arguments.

    The permit itself is produced by the offline kernel issuer with the
    operator's own key; this bundle only adds the authority's attestation that
    the exact scope was approved. Two independent signatures are therefore
    required before a kernel tool can run.
    """
    if type(audience) is not str or not _IDENT.fullmatch(audience):
        raise AuthorityError("INVALID_AUDIENCE")
    if type(actor) is not str or not _ACTOR.fullmatch(actor):
        raise AuthorityError("INVALID_ACTOR")
    if tool not in KERNEL_TOOLS:
        raise AuthorityError("TOOL_NOT_ALLOWLISTED")
    if type(arguments) is not dict:
        raise AuthorityError("INVALID_ARGUMENTS")
    if type(permit_file) is not str or not os.path.isabs(permit_file):
        raise AuthorityError("ABSOLUTE_PATH_REQUIRED")
    if not os.path.isfile(permit_file):
        raise AuthorityError("PERMIT_FILE_MISSING")
    if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 3600:
        raise AuthorityError("INVALID_TTL")
    issued = int(time.time() * 1000) if now_ms is None else now_ms
    payload = {
        "v": 1, "kind": "kernel-permit-bundle",
        "bundle_id": secrets.token_hex(16),
        "audience": audience, "actor": actor, "tool": tool,
        "arguments_sha256": arguments_digest(tool, arguments),
        "permit_file": permit_file, "max_executions": 1,
        "valid_from_ms": issued,
        "valid_until_ms": issued + ttl_seconds * 1000,
        "issued_at_ms": issued,
    }
    key = _load_private_key(private_key_path, passphrase)
    signature = key.sign(BUNDLE_DOMAIN + _canonical(payload)).hex()
    _write_private_json(output_path, {**payload, "signature": signature})
    return {"bundle_id": payload["bundle_id"], "arguments_sha256": payload["arguments_sha256"],
            "output_created": True, "valid_until_ms": payload["valid_until_ms"]}


def load_signed_document(path: str) -> dict:
    """Read a signed document from an owned 0600 file, refusing symlinks."""
    source = Path(path)
    if not source.is_absolute():
        raise AuthorityError("ABSOLUTE_PATH_REQUIRED")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= 65536):
            raise AuthorityError("DOCUMENT_PERMISSIONS")
        data = os.read(fd, 65537)
    finally:
        os.close(fd)
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise AuthorityError("MALFORMED_DOCUMENT") from None
    if type(document) is not dict:
        raise AuthorityError("MALFORMED_DOCUMENT")
    return document


def public_key_from_file(path: str) -> str:
    source = Path(path)
    if not source.is_absolute():
        raise AuthorityError("ABSOLUTE_PATH_REQUIRED")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o022 or not 1 <= info.st_size <= 4096):
            raise AuthorityError("DOCUMENT_PERMISSIONS")
        data = os.read(fd, 4097)
    finally:
        os.close(fd)
    value = data.decode("ascii", "strict").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise AuthorityError("INVALID_PUBLIC_KEY")
    return value


def describe(document: dict) -> dict[str, Any]:
    """Human-facing summary for the approval terminal; never includes secrets."""
    payload = {k: v for k, v in document.items() if k != "signature"}
    return payload
