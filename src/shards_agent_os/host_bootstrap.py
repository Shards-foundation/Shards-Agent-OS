"""Conservative, idempotent installer for a *single-host* trusted sandbox broker.

Requirements: root invocation from a trusted installed Agent OS virtualenv,
existing root-owned verifier configuration, Docker + runsc already working,
and a pre-existing unprivileged agent user. This creates only dedicated host
identities, installs the fixed systemd unit, and optionally starts the service.

No Docker installation, private key creation, image pulling or remote network
access is performed. Explicit --apply and --acknowledge-rootful-docker required.
"""
from __future__ import annotations

import argparse
import grp
import importlib.resources
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from . import host_doctor

_OPERATOR = "shards-sandbox"
_CLIENT_GROUP = "shards-broker-clients"
_VENV = Path("/opt/shards-agent-os/venv")
_UNIT = Path("/etc/systemd/system/shards-agent-os-broker.service")
_CONFIG = Path("/etc/shards-agent-os/broker.env")
_SOURCE_UNIT = "resources/shards-agent-os-broker.service"


def _existing_user(name: str):
    try:
        return pwd.getpwnam(name)
    except KeyError as exc:
        raise RuntimeError("Expected an existing agent account") from exc


def _run(*args: str) -> None:
    subprocess.run(args, timeout=60, check=True, capture_output=True, text=True)


def _preconditions(agent_user: str) -> None:
    """Refuse any mutation until the operator's trust roots are fixed."""
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise PermissionError("Linux root required for host bootstrap")
    if agent_user in {_OPERATOR, "root"} or not agent_user.isascii() or not agent_user.replace("-", "").replace("_", "").isalnum():
        raise ValueError("Unsafe agent name")
    if not Path("/run/systemd/system").is_dir():
        raise RuntimeError("Host must use systemd")
    if sys.prefix != str(_VENV):
        raise RuntimeError("Run from /opt/shards-agent-os/venv/bin/python")
    # The service binary and bundled unit are trusted code. A group-writable
    # installation ancestor would let an agent replace it before startup.
    trusted_paths = (
        Path("/opt"), Path("/opt/shards-agent-os"), _VENV,
        _VENV / "bin", _VENV / "bin" / "shards-agent-os-broker",
        _VENV / "lib",
    )
    for path in trusted_paths:
        info = path.lstat()
        if info.st_uid != 0 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise PermissionError("Trusted package ancestry is not root-owned")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("Trusted package ancestry cannot be group/world writable")
    # The verifier file is intentionally public-key-only but changing it would
    # select a different trust root: its containing directory must be private.
    config_parent = _CONFIG.parent.lstat()
    if (not stat.S_ISDIR(config_parent.st_mode)
        or config_parent.st_uid != 0
        or stat.S_IMODE(config_parent.st_mode) != 0o700):
        raise PermissionError("Pinned verifier directory must be root-owned 0700")
    if not (_VENV / "bin" / "shards-agent-os-broker").is_file():
        raise RuntimeError("Install the Agent OS package before bootstrap")
    agent = _existing_user(agent_user)
    if agent.pw_uid == 0:
        raise PermissionError("Agent cannot be root")
    settings = host_doctor._private_root_config(_CONFIG)
    if agent.pw_uid != int(settings["SHARDS_AGENT_UID"]):
        raise PermissionError("Root-owned verifier configuration pins another agent UID")
    docker_stat = os.stat("/var/run/docker.sock")
    docker_group = grp.getgrgid(docker_stat.st_gid).gr_name
    if docker_group != "docker":
        raise RuntimeError("Docker socket must be restricted to the docker group")
    if docker_stat.st_mode & stat.S_IWOTH:
        raise PermissionError("Docker socket is world writable")
    if docker_stat.st_gid in host_doctor._groups(agent):
        raise PermissionError("Untrusted agent must not access the Docker socket")
    try:
        prior = pwd.getpwnam(_OPERATOR)
        if prior.pw_uid in (0, agent.pw_uid):
            raise PermissionError("Unsafe existing operator identity")
    except KeyError:
        pass
    host_doctor._runtime()
    # A local venv/verified PyPI version is necessary, not sufficient by itself:
    # the operator must still be pinned by its signed policy and OS permissions.
    result = subprocess.run(
        [str(_VENV / "bin" / "python"), "-c",
         'import importlib.metadata as m; assert m.version("shards-kernel") == "0.1.3"'],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("The trusted venv must install Shards-Kernel 0.1.3")


def _ensure_host_accounts(agent_user: str) -> None:
    try:
        group = grp.getgrnam(_CLIENT_GROUP)
    except KeyError:
        _run("groupadd", "--system", _CLIENT_GROUP)
        group = grp.getgrnam(_CLIENT_GROUP)
    if group.gr_gid == grp.getgrnam("docker").gr_gid:
        raise PermissionError("Client group cannot be Docker group")
    try:
        pwd.getpwnam(_OPERATOR)
    except KeyError:
        _run(
            "useradd", "--system", "--home-dir", "/var/lib/shards-sandbox",
            "--shell", "/usr/sbin/nologin", "--gid", _CLIENT_GROUP,
            _OPERATOR,
        )
    _run("usermod", "-aG", _CLIENT_GROUP, agent_user)
    _run("usermod", "-aG", _CLIENT_GROUP, _OPERATOR)
    _run("usermod", "-aG", "docker", _OPERATOR)
    # A subsequent sign-in may be required before an existing agent
    # process sees its newly granted *socket-only* group.


def _install_unit() -> None:
    """Copy the packaged, fixed unit without clobbering an operator edit."""
    directory = _UNIT.parent
    st = directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise PermissionError("Unsafe systemd unit directory")
    source = importlib.resources.files("shards_agent_os").joinpath(_SOURCE_UNIT).read_bytes()
    if len(source) < 200 or b"[Service]" not in source or b"SupplementaryGroups=docker" not in source:
        raise RuntimeError("Packaged service unit is unexpected")
    try:
        existing = _UNIT.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not stat.S_ISREG(existing.st_mode) or existing.st_uid != 0:
            raise PermissionError("Cannot overwrite an untrusted systemd unit")
        if _UNIT.read_bytes() != source:
            raise RuntimeError("Existing systemd service differs; manual review required")
        if stat.S_IMODE(existing.st_mode) != 0o644:
            raise PermissionError("Existing systemd unit must be 0644")
        return
    # Only one installation can succeed, and existing units never get replaced.
    fd = os.open(_UNIT, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(source)
            stream.flush()
            os.fsync(fd)
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)


def bootstrap(agent_user: str, *, start: bool) -> None:
    _preconditions(agent_user)
    _ensure_host_accounts(agent_user)
    _install_unit()
    before = host_doctor.inspect_host(agent=agent_user)
    if not all(check.ok for check in before):
        raise RuntimeError("Host doctor refused startup after provisioning")
    _run("systemctl", "daemon-reload")
    if start:
        _run("systemctl", "enable", "--now", "shards-agent-os-broker.service")
        after = host_doctor.inspect_host(agent=agent_user, running=True)
        if not all(check.ok for check in after):
            raise RuntimeError("Broker started but host doctor did not confirm security checks")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shards-agent-os-bootstrap")
    parser.add_argument("--agent-user", required=True,
                        help="Pre-existing unprivileged OS identity, not an agent name in a prompt")
    parser.add_argument("--apply", action="store_true",
                        help="Provision users/groups and install the systemd unit")
    parser.add_argument("--start", action="store_true",
                        help="Also enable and start the dedicated broker service")
    parser.add_argument("--acknowledge-rootful-docker", action="store_true",
                        help="Acknowledge rootful Docker access is host-root equivalent")
    args = parser.parse_args(argv)
    if args.start and not args.apply:
        parser.error("--start requires --apply")
    if args.apply and not args.acknowledge_rootful_docker:
        parser.error("--apply requires --acknowledge-rootful-docker")
    if not args.apply:
        print("PLAN ONLY: verify Docker/runsc, root-owned public verifier, "
              "fixed trusted venv and separate agent UID; create client-only "
              "group and operator account; install fixed systemd unit. "
              "Nothing was changed.")
        return 0
    try:
        bootstrap(args.agent_user, start=args.start)
    except Exception:
        print("Sandbox host bootstrap refused or failed. No deployment success "
              "is claimed; inspect trusted administrator diagnostics.", file=sys.stderr)
        return 2
    print("Sandbox host bootstrap applied; "
          + ("service running and doctor checks passed"
             if args.start else "systemd unit installed but service not started"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
