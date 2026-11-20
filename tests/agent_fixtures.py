"""Shared fixtures for the governed-agent tests.

Everything here is ephemeral and local: throw-away Ed25519 keys, a private
temporary SQLite directory and (where needed) a real signed Shards-Kernel
operator on a loopback port. No production credential is used or required.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from shards_agent_os import agent_state, agent_tools
from shards_agent_os.agent_loop import ToolAuthority, ensure_agent_schema
from shards_agent_os.qwen_provider import ModelReply
from shards_agent_os.tool_permit_authority import (
    arguments_digest, issue_delegation, issue_kernel_bundle, generate_authority_key,
)

AUDIENCE = "agent-os-test-instance"
ACTOR = "owner@example.test"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Workspace:
    """Private temp dir with a valid Agent OS database and a web-ready config."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.db_path = str(self.root / "state.sqlite3")
        ensure_agent_schema(self.db_path)
        agent_state.recover_incomplete_turns(self.db_path)
        self.actor = ACTOR
        self.audience = AUDIENCE
        self.authority_private = str(self.root / "authority-private.pem")
        self.authority_public = str(self.root / "authority-public.hex")
        generate_authority_key(
            private_path=self.authority_private, public_path=self.authority_public,
            passphrase=b"test-passphrase-0123456789",
        )
        self.passphrase = b"test-passphrase-0123456789"

    def delegation(self, *, tools=("os.queue_summary", "os.halt_state"),
                   max_executions: int = 50, actor: str | None = None,
                   audience: str | None = None, ttl_seconds: int = 3600) -> str:
        path = str(self.root / f"delegation-{secrets.token_hex(4)}.json")
        issue_delegation(
            private_key_path=self.authority_private, passphrase=self.passphrase,
            output_path=path, audience=audience or self.audience,
            actor=actor or self.actor, tools=list(tools),
            max_executions=max_executions, ttl_seconds=ttl_seconds,
        )
        return path

    def bundle(self, *, tool: str, arguments: dict, permit_file: str,
               actor: str | None = None) -> str:
        digest = arguments_digest(tool, arguments)
        path = str(self.root / f"{digest}.json")
        issue_kernel_bundle(
            private_key_path=self.authority_private, passphrase=self.passphrase,
            output_path=path, permit_file=permit_file, audience=self.audience,
            actor=actor or self.actor, tool=tool, arguments=arguments,
            ttl_seconds=900,
        )
        return path

    def authority(self, *, delegation_file: str | None = None,
                  bundles: dict[str, str] | None = None) -> ToolAuthority:
        from shards_agent_os.tool_permit_authority import public_key_from_file

        return ToolAuthority(
            public_key_hex=public_key_from_file(self.authority_public),
            audience=self.audience, delegation_file=delegation_file,
            bundles=bundles or {},
        )

    def conversation(self, actor: str | None = None) -> str:
        return agent_state.create_conversation(self.db_path, actor=actor or self.actor)

    def close(self) -> None:
        self._tmp.cleanup()


class ScriptedProvider:
    """Deterministic stand-in for a model, for protocol and governance tests.

    Named ``scripted`` rather than ``fixture`` on purpose: tests that use it
    are testing the *loop*, not claiming real inference. Real Qwen evidence
    lives in ``test_agent_qwen_live.py``.
    """

    name = "scripted"
    model = "scripted/local"

    def __init__(self, *replies: str) -> None:
        self._replies = list(replies)
        self.calls: list[dict[str, str]] = []

    def complete(self, *, system: str, user: str, timeout_s: float) -> ModelReply:
        self.calls.append({"system": system, "user": user})
        text = self._replies[min(len(self.calls) - 1, len(self._replies) - 1)]
        return ModelReply(text=text, provider=self.name, model=self.model, latency_ms=3)


def decision(reply: str, tool: str | None = None, arguments: dict | None = None) -> str:
    payload: dict = {"reply": reply, "tool": None}
    if tool is not None:
        payload["tool"] = {"name": tool, "arguments": arguments if arguments is not None else {}}
    return json.dumps(payload)


def write_private_json(path: str, payload: dict) -> str:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(payload, stream)
    return path


def write_signed_kernel_policy(root: Path, *, agents: list[dict], tools: list[str],
                               port: int, audit_db: Path):
    """Prepare a signed test policy and its operator-only environment."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from shards_kernel.integrations.auth import agent_token_kdf
    from shards_kernel.issuer import sign_operator_policy

    enrolled = list(agents)
    enrolled.append({
        "actor": "unused-second-identity",
        "token": "unused-second-identity." + secrets.token_urlsafe(48),
        "allowed_tools": ["echo"],
    })
    agents = enrolled
    issuer = Ed25519PrivateKey.generate()
    policy_issuer = Ed25519PrivateKey.generate()
    pepper = secrets.token_urlsafe(48)
    now = int(time.time() * 1000)
    policy = {
        "version": 2, "kernel_id": AUDIENCE, "tools": tools,
        "agents": [
            {"actor": item["actor"],
             "token_scrypt": agent_token_kdf(item["token"], pepper.encode()),
             "allowed_tools": item["allowed_tools"]}
            for item in agents
        ],
        "issuer_keys": [{
            "key_id": "permit-issuer", "issuer": "operator",
            "public_key_hex": issuer.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(audit_db),
        "port": port,
    }
    signed = sign_operator_policy(policy, policy_issuer, revision=1,
                                  issued_at_ms=now - 60_000, expires_at_ms=now + 900_000)
    policy_file = root / "signed-operator.json"
    policy_file.write_text(json.dumps(signed))
    env = {
        "SHARDS_KERNEL_API_KEY": secrets.token_urlsafe(48),
        "SHARDS_KERNEL_AGENT_AUTH_PEPPER": pepper,
        "SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX":
            policy_issuer.public_key().public_bytes_raw().hex(),
    }
    return policy_file, env, {"issuer": issuer, "policy_issuer": policy_issuer}


def start_signed_kernel(root: Path, *, agents: list[dict], tools: list[str],
                        port: int | None = None):
    """Start a real signed Shards-Kernel operator. Returns (proc, port, ctx).

    The kernel's signed policy requires at least two distinct agent identities,
    so a second, unused identity is always enrolled. It has no token in the
    environment and cannot be assumed by the caller.
    """
    port = port or free_port()
    policy_file, operator_env, ctx = write_signed_kernel_policy(
        root, agents=agents, tools=tools, port=port, audit_db=root / "kernel_audit.sqlite3",
    )
    env = {**os.environ, **operator_env}
    import subprocess
    import sys

    proc = subprocess.Popen(
        [sys.executable, "-m", "shards_kernel", "serve", "--config", str(policy_file)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    healthy = False
    for _ in range(200):
        if proc.poll() is not None:
            break
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.3) as resp:
                if resp.status == 200 and json.loads(resp.read()).get("status") == "healthy":
                    healthy = True
                    break
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    if not healthy:
        proc.terminate()
        raise RuntimeError("Signed kernel operator did not become healthy")
    return proc, port, ctx


def issue_echo_permit(root: Path, ctx, *, text: str, subject: str,
                      path: str | None = None) -> str:
    """Issue one real signed single-use kernel permit for an echo call."""
    from shards_kernel.integrations.wire import permit_to_mapping
    from shards_kernel.issuer import sign_v2_permit
    from shards_kernel.permits import PermitBuilder

    now = int(time.time() * 1000)
    permit = (
        PermitBuilder().issuer("operator").subject(subject)
        .jurisdiction("default").action("echo").params({"text": text})
        .max_executions(1).valid_from_ms(now - 30_000).valid_until_ms(now + 600_000)
        .proposal_hash(f"approved-{subject}").build_unsigned_v2(
            key_id="permit-issuer", audience=AUDIENCE,
        )
    )
    signed = permit_to_mapping(sign_v2_permit(permit, ctx["issuer"]))
    target = path or str(root / f"permit-{secrets.token_hex(8)}.json")
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(signed, stream)
    return target


def issue_add_permit(root: Path, ctx, *, a, b, subject: str) -> str:
    from shards_kernel.integrations.wire import permit_to_mapping
    from shards_kernel.issuer import sign_v2_permit
    from shards_kernel.permits import PermitBuilder

    now = int(time.time() * 1000)
    permit = (
        PermitBuilder().issuer("operator").subject(subject)
        .jurisdiction("default").action("add").params({"a": a, "b": b})
        .max_executions(1).valid_from_ms(now - 30_000).valid_until_ms(now + 600_000)
        .proposal_hash(f"approved-{subject}").build_unsigned_v2(
            key_id="permit-issuer", audience=AUDIENCE,
        )
    )
    signed = permit_to_mapping(sign_v2_permit(permit, ctx["issuer"]))
    target = str(root / f"permit-{secrets.token_hex(8)}.json")
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(signed, stream)
    return target


def file_fingerprint(path: str) -> tuple:
    """inode + mtime + size: content hashing cannot detect an identical rewrite."""
    info = os.stat(path)
    return (info.st_ino, info.st_mtime_ns, info.st_size)
