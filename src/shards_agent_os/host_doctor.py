"""Non-mutating verification of one controlled Linux sandbox broker host.

No key material, Docker socket, audit contents or user tokens are written to
stdout. A failed precondition causes a nonzero exit and an actionable check ID.
This is a host pilot preflight, not a security certification.
"""
from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import re
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

_ENV_KEYS = frozenset({
    "SHARDS_AGENT_UID", "SHARDS_KERNEL_ID", "SHARDS_ACTOR",
    "SHARDS_ISSUER_ID", "SHARDS_KEY_ID", "SHARDS_ISSUER_PUBLIC_HEX",
})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _check(name: str, fn) -> Check:
    try:
        detail = fn()
        return Check(name, True, str(detail))
    except Exception as exc:
        # Never echo exception text: it might contain credentials or audit paths.
        return Check(name, False, type(exc).__name__)


def _parse_environment(body: bytes) -> dict[str, str]:
    if len(body) > 4096 or b"\x00" in body:
        raise ValueError("Config invalid")
    values: dict[str, str] = {}
    for original in body.decode("utf-8").splitlines():
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("Malformed environment setting")
        key, value = line.split("=", 1)
        if key not in _ENV_KEYS or key in values or not value or value.strip() != value:
            raise ValueError("Unexpected, duplicated or empty environment field")
        values[key] = value
    if values.keys() != _ENV_KEYS:
        raise ValueError("Missing required environment values")
    if (not values["SHARDS_AGENT_UID"].isdigit()
        or int(values["SHARDS_AGENT_UID"]) <= 0
        or any(not _IDENTIFIER.fullmatch(values[key]) for key in (
            "SHARDS_KERNEL_ID", "SHARDS_ACTOR", "SHARDS_ISSUER_ID", "SHARDS_KEY_ID"
        ))
        or not _HEX.fullmatch(values["SHARDS_ISSUER_PUBLIC_HEX"])):
        raise ValueError("Invalid environment setting")
    return values


def _private_root_config(path: Path) -> dict[str, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError("Root-owned mode 0600 config required")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        actual = os.fstat(fd)
        if (actual.st_ino, actual.st_dev) != (info.st_ino, info.st_dev):
            raise RuntimeError("Config changed")
        if actual.st_size > 4096 or actual.st_size < 40:
            raise ValueError("Config size invalid")
        body = os.read(fd, 4097)
    finally:
        os.close(fd)
    return _parse_environment(body)


def _user(name: str):
    person = pwd.getpwnam(name)
    if person.pw_uid <= 0:
        raise ValueError("Expected a nonroot service identity")
    return person


def _groups(person) -> set[int]:
    return set(os.getgrouplist(person.pw_name, person.pw_gid))


def _identities(operator: str, agent: str, client_group: str) -> str:
    op = _user(operator)
    ag = _user(agent)
    if op.pw_uid == ag.pw_uid:
        raise PermissionError("Agent shares operator UID")
    g = grp.getgrnam(client_group)
    docker_group = os.stat("/var/run/docker.sock").st_gid
    if g.gr_gid == docker_group:
        raise PermissionError("Client group must not equal Docker socket group")
    operator_groups = _groups(op)
    agent_groups = _groups(ag)
    if g.gr_gid not in operator_groups or g.gr_gid not in agent_groups:
        raise PermissionError("Broker client group must include both identities")
    if docker_group in agent_groups:
        raise PermissionError("Agent must not belong to Docker socket group")
    if docker_group not in operator_groups:
        raise PermissionError("Operator must have Docker socket group")
    if os.stat("/var/run/docker.sock").st_mode & stat.S_IWOTH:
        raise PermissionError("Docker socket cannot be world writable")
    return "Separate nonroot UIDs; agent denied Docker group"


def _runtime() -> str:
    if not sys.platform.startswith("linux"):
        raise OSError("Linux required")
    result = subprocess.run(
        ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock",
         "info", "--format", "{{json .Runtimes}}"],
        capture_output=True, text=True, timeout=12, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0 or len(result.stdout) > 16384:
        raise OSError("Cannot inspect local Docker runtimes")
    runtimes = json.loads(result.stdout)
    if type(runtimes) is not dict or "runsc" not in runtimes:
        raise RuntimeError("gVisor runsc is not registered")
    return "Docker daemon has runsc runtime"


def _path(path: Path, *, mode: int, owner_uid: int, group_gid: int | None = None, kind: str) -> str:
    info = path.lstat()
    if (info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != mode
        or (group_gid is not None and info.st_gid != group_gid)):
        raise PermissionError("Incorrect mode, owner, or group")
    expected = {"dir": stat.S_ISDIR, "socket": stat.S_ISSOCK, "file": stat.S_ISREG}[kind]
    if not expected(info.st_mode):
        raise ValueError("Unexpected filesystem object")
    return "Ownership and permissions verified"


def _socket(socket_path: Path, operator_uid: int, client_group: int) -> str:
    _path(socket_path, mode=0o660, owner_uid=operator_uid,
          group_gid=client_group, kind="socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.5)
        sock.connect(str(socket_path))
        if not hasattr(socket, "SO_PEERCRED"):
            raise OSError("SO_PEERCRED unsupported")
        # A successful connection only proves that a broker-like listener exists.
        # It does not prove that this server actually validates signed permits.
    return "Socket is listening with restricted owner and group"


def inspect_host(
    *, operator: str = "shards-sandbox",
    agent: str = "shards-agent",
    group: str = "shards-broker-clients",
    environment: str = "/etc/shards-agent-os/broker.env",
    unit: str = "/etc/systemd/system/shards-agent-os-broker.service",
    running: bool = False,
) -> list[Check]:
    """Return non-mutating checks in fixed order; never short-circuit."""
    results = [
        _check("linux", lambda: "Linux host" if sys.platform.startswith("linux")
               else (_ for _ in ()).throw(OSError("Linux required"))),
        _check("docker_runsc", _runtime),
        _check("identities", lambda: _identities(operator, agent, group)),
    ]
    def config_check():
        settings = _private_root_config(Path(environment))
        if int(settings["SHARDS_AGENT_UID"]) != _user(agent).pw_uid:
            raise ValueError("Configured agent UID differs from host")
        return "Pinned public verifier and agent UID valid"
    results.append(_check("signed_operator_config", config_check))
    results.append(_check(
        "trusted_unit", lambda: _path(
            Path(unit), mode=0o644, owner_uid=0, kind="file",
        ),
    ))
    if running:
        op = None
        client_gid = None
        try:
            op = _user(operator)
            client_gid = grp.getgrnam(group).gr_gid
        except (KeyError, ValueError):
            pass
        results.extend([
            _check("state_dir", lambda: _path(
                Path("/var/lib/shards-sandbox"),
                mode=0o700, owner_uid=op.pw_uid, kind="dir")),
            _check("socket_dir", lambda: _path(
                Path("/run/shards-sandbox"),
                mode=0o750, owner_uid=op.pw_uid,
                group_gid=client_gid, kind="dir")),
            _check("agent_socket", lambda: _socket(
                Path("/run/shards-sandbox/broker.sock"),
                operator_uid=op.pw_uid, client_group=client_gid)),
        ])
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shards-agent-os-doctor")
    parser.add_argument("--agent-user", default="shards-agent")
    parser.add_argument("--operator-user", default="shards-sandbox")
    parser.add_argument("--client-group", default="shards-broker-clients")
    parser.add_argument("--environment-file", default="/etc/shards-agent-os/broker.env")
    parser.add_argument("--unit-file", default="/etc/systemd/system/shards-agent-os-broker.service")
    parser.add_argument("--running", action="store_true",
                        help="Also verify broker state and listening socket")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    checks = inspect_host(
        operator=args.operator_user, agent=args.agent_user,
        group=args.client_group, environment=args.environment_file,
        unit=args.unit_file, running=args.running,
    )
    ok = all(c.ok for c in checks)
    if args.json:
        print(json.dumps({
            "ok": ok, "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail}
                                for c in checks],
        }, sort_keys=True))
    else:
        for c in checks:
            print(("[OK] " if c.ok else "[FAIL] ") + c.name + ": " + c.detail)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
