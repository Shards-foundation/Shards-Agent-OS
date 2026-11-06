"""Linux-only, fail-closed gVisor executor for a *trusted* operator.

This module intentionally does not expose a tool to an agent. The caller must
first obtain an independent Shards-Kernel ALLOW for the exact ExecutionSpec.
Docker socket access belongs exclusively to the trusted host supervisor.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass

IMAGE_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,190}@sha256:[0-9a-f]{64}\Z")
OUTPUT_LIMIT = 65536
DOCKER_HOST = "unix:///var/run/docker.sock"


class SandboxUnavailable(RuntimeError):
    """No verified gVisor-capable local runtime is available."""


@dataclass(frozen=True)
class ExecutionSpec:
    """Explicit, immutable workload parameters; must be bound in a signed permit."""

    image: str
    argv: tuple[str, ...]
    timeout_seconds: int = 20
    memory_megabytes: int = 256
    cpu_millicores: int = 500
    pids_limit: int = 32

    def __post_init__(self) -> None:
        if type(self.image) is not str or not IMAGE_RE.fullmatch(self.image):
            raise ValueError("Image must be a canonical sha256-pinned OCI reference")
        if type(self.argv) is not tuple or not 1 <= len(self.argv) <= 32:
            raise ValueError("argv must be a nonempty tuple with at most 32 entries")
        if any(type(x) is not str or not x or len(x) > 1024 or
               any(ord(char) < 32 for char in x) for x in self.argv):
            raise ValueError("Invalid command argument")
        if sum(len(x) for x in self.argv) > 8192:
            raise ValueError("Command arguments exceed 8192 characters")
        for key, low, high in (
            ("timeout_seconds", 1, 120),
            ("memory_megabytes", 64, 1024),
            ("cpu_millicores", 100, 2000),
            ("pids_limit", 8, 128),
        ):
            value = getattr(self, key)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{key} must be an integer in [{low}, {high}]")

    def fingerprint(self) -> str:
        """Stable binding to the workload configuration, not authorisation."""
        payload = {
            "image": self.image, "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "memory_megabytes": self.memory_megabytes,
            "cpu_millicores": self.cpu_millicores,
            "pids_limit": self.pids_limit,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class SandboxResult:
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    fingerprint: str
    cleanup_confirmed: bool


class GVisorExecutor:
    """Run a bounded OCI workload with Docker's explicitly selected runsc runtime.

    Only trusted host code may call this class. No shell, network, image pulling,
    host bind mounts, credentials, host namespace sharing or privilege escalation.
    """

    def __init__(self, *, docker_binary: str | None = None):
        self._docker = docker_binary or shutil.which("docker")
        if not self._docker or not os.path.isabs(self._docker):
            raise SandboxUnavailable("A trusted absolute-path Docker CLI is required")

    def _base(self) -> list[str]:
        return [self._docker, "--host", DOCKER_HOST]

    def _preflight(self, env: dict[str, str]) -> None:
        if not sys.platform.startswith("linux"):
            raise SandboxUnavailable("gVisor execution requires a Linux host")
        try:
            check = subprocess.run(
                self._base() + ["info", "--format", "{{json .Runtimes}}"],
                capture_output=True, text=True, timeout=10, env=env, check=False,
            )
            runtimes = json.loads(check.stdout) if check.returncode == 0 else {}
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise SandboxUnavailable("Cannot inspect local Docker runtimes") from exc
        if not isinstance(runtimes, dict) or "runsc" not in runtimes:
            raise SandboxUnavailable("Docker must explicitly register the runsc runtime")

    def _command(self, spec: ExecutionSpec, name: str) -> list[str]:
        return self._base() + [
            "run", "--rm", "--pull=never", "--runtime=runsc",
            "--name", name, "--label", "shards.agent-os.sandbox=1",
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges",
            "--user", "65532:65532", "--workdir", "/tmp",
            "--ipc=none", "--pids-limit", str(spec.pids_limit),
            "--memory", f"{spec.memory_megabytes}m",
            "--memory-swap", f"{spec.memory_megabytes}m",
            "--cpus", f"{spec.cpu_millicores / 1000:.3f}",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
            "--log-driver=none",
            spec.image, *spec.argv,
        ]

    @staticmethod
    def _collect(proc: subprocess.Popen, deadline: float) -> tuple[str, bytes, bytes]:
        """Drain both pipes with bounded memory; never trust container output size."""
        outputs = [bytearray(), bytearray()]
        status = "EXITED"
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((proc.stdout, proc.stderr)):
                if stream is not None:
                    selector.register(stream, selectors.EVENT_READ, index)
            while True:
                if proc.poll() is not None and not selector.get_map():
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "TIMEOUT"
                    break
                for key, _ in selector.select(min(remaining, 0.25)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if sum(map(len, outputs)) + len(chunk) > OUTPUT_LIMIT:
                        status = "OUTPUT_LIMIT"
                        break
                    outputs[key.data].extend(chunk)
                if status == "OUTPUT_LIMIT":
                    break
        return status, bytes(outputs[0]), bytes(outputs[1])

    def _cleanup(self, name: str, env: dict[str, str]) -> bool:
        """Remove/kill the named container and *verify* that it is gone."""
        try:
            subprocess.run(
                self._base() + ["container", "rm", "--force", "--volumes", name],
                capture_output=True, timeout=15, env=env, check=False,
            )
            probe = subprocess.run(
                self._base() + ["container", "inspect", name],
                capture_output=True, text=True, timeout=10, env=env, check=False,
            )
            return probe.returncode != 0 and "No such container" in probe.stderr
        except (OSError, subprocess.TimeoutExpired):
            return False

    def run(self, spec: ExecutionSpec) -> SandboxResult:
        """Execute from a trusted host only; never accepts agent-made authorisation.

        Callers must enforce a signed-permit decision *before* calling this.
        An UNKNOWN result means container termination could not be proven.
        """
        if type(spec) is not ExecutionSpec:
            raise TypeError("An exact, validated ExecutionSpec is required")
        with tempfile.TemporaryDirectory(prefix="shards-docker-config-") as config:
            env = {"PATH": "/usr/bin:/bin", "HOME": config, "DOCKER_CONFIG": config,
                   "LC_ALL": "C"}
            self._preflight(env)
            name = "shards-sbx-" + uuid.uuid4().hex
            started = time.monotonic()
            try:
                proc = subprocess.Popen(
                    self._command(spec, name), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env=env, close_fds=True, bufsize=0, start_new_session=True,
                )
            except OSError as exc:
                raise SandboxUnavailable("Unable to launch Docker CLI") from exc
            try:
                status, stdout, stderr = self._collect(
                    proc, started + spec.timeout_seconds
                )
            finally:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
                cleaned = self._cleanup(name, env)
            duration_ms = int((time.monotonic() - started) * 1000)
            if not cleaned:
                status = "UNKNOWN"
            elif status == "EXITED" and proc.returncode != 0:
                status = "PROCESS_ERROR"
            return SandboxResult(
                status=status, exit_code=proc.returncode,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                duration_ms=duration_ms, fingerprint=spec.fingerprint(),
                cleanup_confirmed=cleaned,
            )
