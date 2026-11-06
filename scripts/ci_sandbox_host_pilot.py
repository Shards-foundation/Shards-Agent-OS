"""Ephemeral GitHub Actions Linux host installation and signed effect smoke.

This intentionally modifies the disposable CI host's users/systemd, and MUST
NOT be run on a real system. Requires explicit SHARDS_HOST_PILOT_CI=1 and the
GitHub-hosted Actions environment. Signing private key is kept in the test
controller process; the broker receives only the public verification key.
"""
from __future__ import annotations

import json
import os
import pwd
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.permits import PermitBuilder


def command(argv, *, input=None, accept=0, timeout=50):
    result = subprocess.run(
        argv, input=input, capture_output=True, text=True, timeout=timeout,
        check=False,
    )
    if result.returncode != accept:
        # Only copy the fixed-phase, secret-free bootstrap failure marker.
        # Raw subprocess stderr can contain sensitive host information.
        diagnostic = ""
        if any("shards-agent-os-bootstrap" in arg for arg in argv):
            approved = next(
                (line for line in result.stderr.splitlines()
                 if line.startswith("Sandbox host bootstrap refused:")),
                "",
            )
            diagnostic = " [phase=" + approved[:180] + "]"
        raise RuntimeError(
            f"CI host command failed (exit={result.returncode}): {argv[0:2]!r}"
            + diagnostic
        )
    return result.stdout.strip()


def provision_verifier(agent_uid: int, public_hex: str) -> None:
    command([
        "sudo", "-n", "install", "-d", "-m", "0700", "-o", "root", "-g", "root",
        "/etc/shards-agent-os",
    ])
    settings = "\n".join((
        f"SHARDS_AGENT_UID={agent_uid}",
        "SHARDS_KERNEL_ID=sandbox-pilot-e2e",
        "SHARDS_ACTOR=agent-alpha",
        "SHARDS_ISSUER_ID=independent-approver",
        "SHARDS_KEY_ID=approver-public",
        f"SHARDS_ISSUER_PUBLIC_HEX={public_hex}",
    )) + "\n"
    # File created O_EXCL at 0600 directly; no briefly world-readable
    # verifier configuration and no private signing key on the service side.
    source = (
        "import os,sys; "
        "p='/etc/shards-agent-os/broker.env'; "
        "fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); "
        "os.write(fd,sys.stdin.buffer.read()); os.fsync(fd); os.close(fd)"
    )
    command(["sudo", "-n", "/usr/bin/python3", "-c", source], input=settings)


def signed_permit(private, args):
    now = int(time.time() * 1000)
    token = (
        PermitBuilder()
        .issuer("independent-approver")
        .subject("agent-alpha")
        .jurisdiction("default")
        .action("sandbox.exec")
        .params(args)
        .max_executions(1)
        .valid_from_ms(now - 30000)
        .valid_until_ms(now + 120000)
        .proposal_hash("ci-external-approval")
        .build_unsigned_v2(
            key_id="approver-public", audience="sandbox-pilot-e2e",
        )
    )
    return permit_to_mapping(sign_v2_permit(token, private))


def main() -> int:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("SHARDS_HOST_PILOT_CI") != "1"
        or os.geteuid() == 0
        or not Path("/opt/shards-agent-os/venv/bin/shards-agent-os-bootstrap").exists()
    ):
        raise SystemExit("Refusing to modify an unverified/non-ephemeral CI host")
    # The test runner identity must not be the deployed operator or agent.
    command([
        "sudo", "-n", "useradd", "--system", "--no-create-home",
        "--shell", "/usr/sbin/nologin", "shards-agent",
    ])
    agent_uid = pwd.getpwnam("shards-agent").pw_uid
    key = Ed25519PrivateKey.generate()
    public_hex = key.public_key().public_bytes_raw().hex()
    provision_verifier(agent_uid, public_hex)

    command([
        "sudo", "-n", "/opt/shards-agent-os/venv/bin/shards-agent-os-bootstrap",
        "--agent-user", "shards-agent", "--apply", "--start",
        "--acknowledge-rootful-docker",
    ], timeout=120)
    report = json.loads(command([
        "sudo", "-n", "/opt/shards-agent-os/venv/bin/shards-agent-os-doctor",
        "--agent-user", "shards-agent", "--running", "--json",
    ]))
    if not report.get("ok"):
        raise AssertionError("Running service failed host doctor checks")

    # The client has a usable broker group, but cannot control the Docker host.
    direct = subprocess.run([
        "sudo", "-n", "-u", "shards-agent", "/usr/bin/python3", "-c",
        "import socket; s=socket.socket(socket.AF_UNIX); "
        "s.connect('/var/run/docker.sock')",
    ], capture_output=True, timeout=10)
    if direct.returncode == 0:
        raise AssertionError("Agent unexpectedly has Docker socket access")

    image = os.environ["SHARDS_SANDBOX_IMAGE"]
    if "@sha256:" not in image:
        raise AssertionError("Image is not digest pinned")
    params = {
        "image": image,
        "argv": ["/bin/echo", "systemd-pilot-verified"],
        "timeout_seconds": 20,
        "memory_megabytes": 256,
        "cpu_millicores": 500,
        "pids_limit": 32,
    }
    signature = signed_permit(key, params)
    # A second, distinct signed permit proves actual Agent OS scheduled-job
    # dispatch, not merely direct access to the local broker socket.
    queued_params = {**params, "argv": ["/bin/echo", "scheduled-gvisor-verified"]}
    queued_signature = signed_permit(key, queued_params)
    with tempfile.TemporaryDirectory(prefix="shards-host-pilot-") as root:
        directory = Path(root)
        arguments = directory / "arguments.json"
        permit = directory / "permit.json"
        scheduled_args = directory / "scheduled-arguments.json"
        scheduled_permit = directory / "scheduled-permit.json"
        for dest, value in (
            (arguments, params), (permit, signature),
            (scheduled_args, queued_params), (scheduled_permit, queued_signature),
        ):
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, json.dumps(value, separators=(",", ":")).encode())
            finally:
                os.close(fd)
        command([
            "sudo", "-n", "chown", "-R", "shards-agent", str(directory),
        ])
        try:
            client = [
                "sudo", "-n", "-u", "shards-agent",
                "/opt/shards-agent-os/venv/bin/shards-agent-os-sandbox-call",
                "--socket", "/run/shards-sandbox/broker.sock",
                "--operator-uid", str(pwd.getpwnam("shards-sandbox").pw_uid),
                "--arguments-file", str(arguments),
                "--permit-file", str(permit),
            ]
            accepted = json.loads(command(client))
            if (accepted.get("decision") != "ALLOW"
                or accepted.get("result", {}).get("stdout", "").strip()
                    != "systemd-pilot-verified"):
                raise AssertionError("Signed real systemd broker workload failed")
            denied = json.loads(command(client, accept=2))
            if denied.get("decision") != "DENY":
                raise AssertionError("The consumed permit was accepted twice")

            scheduler = [
                "sudo", "-n", "-u", "shards-agent",
                "/opt/shards-agent-os/venv/bin/shards-agent-os",
                "--db", str(directory / "os-jobs.sqlite3"),
            ]
            enqueue_args = [
                "sandbox-enqueue", "--operator-uid",
                str(pwd.getpwnam("shards-sandbox").pw_uid),
                "--arguments-file", str(scheduled_args),
                "--permit-file", str(scheduled_permit),
            ]
            enqueued = json.loads(command(scheduler + enqueue_args))
            if enqueued.get("status") != "PENDING" or enqueued.get("authorised") is not False:
                raise AssertionError("Sandbox job submission did not remain pending approval")
            scheduled = json.loads(command(scheduler + ["sandbox-run-once"]))
            if (scheduled.get("status") != "SUCCEEDED"
                or scheduled.get("job_id") != enqueued.get("job_id")
                or scheduled.get("receipt", {}).get("stdout", "").strip()
                    != "scheduled-gvisor-verified"
                or scheduled.get("receipt", {}).get("cleanup_confirmed") is not True):
                raise AssertionError("Scheduled Agent OS gVisor execution failed")
            listing = json.loads(command(scheduler + ["sandbox-list"]))
            if (len(listing.get("jobs", [])) != 1
                or listing["jobs"][0].get("status") != "SUCCEEDED"
                or str(scheduled_permit) in json.dumps(listing)):
                raise AssertionError("Sandbox job state or permit-path privacy invalid")

            # A second queued attempt with the same permit must DENY:
            # distinct job IDs never reset the kernel's nonce consumption.
            command(scheduler + enqueue_args)
            replay_job = json.loads(command(scheduler + ["sandbox-run-once"]))
            if replay_job.get("status") != "DENIED":
                raise AssertionError("Re-enqueueing consumed sandbox permit succeeded")
            if json.loads(command(scheduler + ["sandbox-run-once"])).get(
                "status"
            ) != "NO_DUE_SANDBOX_JOB":
                raise AssertionError("Terminal sandbox job was implicitly retried")

            command(["sudo", "-n", "systemctl", "restart",
                     "shards-agent-os-broker.service"])
            # systemctl Type=simple does not guarantee the Unix socket is bound.
            # Never retry an UNKNOWN signed operation: wait for a separate
            # read-only readiness probe *before* issuing the replay test.
            doctor_call = [
                "sudo", "-n", "/opt/shards-agent-os/venv/bin/shards-agent-os-doctor",
                "--agent-user", "shards-agent", "--running", "--json",
            ]
            for _attempt in range(50):
                ready = subprocess.run(
                    doctor_call, capture_output=True, text=True,
                    timeout=15, check=False,
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("Restarted broker never reached trusted readiness")
            after_restart = json.loads(command(client, accept=2))
            if after_restart.get("decision") != "DENY":
                raise AssertionError("Permit replay after systemd restart was accepted")
            command(["sudo", "-n", "systemctl", "is-active",
                     "shards-agent-os-broker.service"])
            # Auditable storage remains entirely unreadable to the agent account.
            state_probe = subprocess.run([
                "sudo", "-n", "-u", "shards-agent", "/usr/bin/python3", "-c",
                "from pathlib import Path; "
                "Path('/var/lib/shards-sandbox/audit.sqlite3').read_bytes()",
            ], capture_output=True, timeout=10)
            if state_probe.returncode == 0:
                raise AssertionError("Agent could read the trusted audit ledger")
        finally:
            # Restore directory ownership to the test runner even when
            # assertions fail, so TemporaryDirectory cleanup can succeed.
            command([
                "sudo", "-n", "chown", "-R",
                f"{os.getuid()}:{os.getgid()}", str(directory),
            ])
    print("PASS: real systemd service, external permits, separate Linux UIDs, "
          "direct and durable Agent OS gVisor execution, Docker/audit denial, "
          "replay denial, no implicit retries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
