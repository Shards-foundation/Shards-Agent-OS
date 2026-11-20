"""Exercise the staging units on a disposable GitHub-hosted ARM64 VM."""
from __future__ import annotations

import http.client
import json
import os
import platform
import secrets
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

from shards_agent_os.web_server import sign_assertion
from tests.agent_fixtures import ACTOR, AUDIENCE, Workspace, issue_echo_permit, write_signed_kernel_policy

CONFIG = Path("/etc/shards-agent-stage")
KERNEL_STATE = Path("/var/lib/shards-stage-kernel/audit.sqlite3")
WEB_STATE = Path("/var/lib/shards-stage-web/agent.sqlite3")
PYTHON = "/opt/shards-agent-stage/venv/bin/python"
UNITS = ("shards-stage-kernel.service", "shards-stage-origin.service")
PUBLIC_HOST = "stage.example.test"


def request(port, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.getheader("Set-Cookie"), response.read()
    finally:
        conn.close()


def ready():
    deadline = time.monotonic() + 25
    observed = {}
    while time.monotonic() < deadline:
        for port, path in ((18765, "/health"), (12026, "/agent-os/")):
            try:
                observed[port] = request(port, path)[0]
            except OSError as exc:
                observed[port] = type(exc).__name__
        if observed == {18765: 200, 12026: 403}:
            return
        time.sleep(0.2)
    for unit in UNITS:
        subprocess.run(["systemctl", "show", unit, "-p", "Id", "-p", "SubState",
                        "-p", "Result", "-p", "ExecMainStatus", "-p", "NRestarts"], check=True)
        # These are disposable services with generated test configuration. Only print
        # error codes from the origin's structured refusal messages.
        messages = subprocess.check_output(["journalctl", "-b", "-u", unit,
                                            "-o", "cat", "-n", "20"], text=True)
        for line in messages.splitlines():
            if line.startswith('{"status": "REFUSED"'):
                print(unit, json.loads(line)["error"])
    raise RuntimeError(f"Staging readiness failed. HTTP results by port: {observed}")


def call_kernel(token, permit):
    result = subprocess.run([
        "/usr/sbin/runuser", "-u", "shards-stage-web", "--", PYTHON, "-I", "-m", "shards_kernel",
        "mcp-call", "--port", "18765", "--tool", "echo",
        "--arguments-json", '{"text":"arm64-stage"}', "--permit-file", str(permit),
    ], env={"PATH": os.defpath, "SHARDS_KERNEL_AGENT_TOKEN": token},
        capture_output=True, text=True, timeout=25)
    return result.returncode, json.loads(result.stdout)


def allowed_audit_entries(request_id):
    with sqlite3.connect(f"file:{KERNEL_STATE}?mode=ro", uri=True) as conn:
        return conn.execute(
            "SELECT ledger_seq, entry_hash FROM audit_entries WHERE kernel_id=? "
            "AND request_id=? AND decision='ALLOW' ORDER BY ledger_seq", (AUDIENCE, request_id)
        ).fetchall()


def env_file(path, settings):
    with path.open("x") as stream:
        for key, value in settings.items():
            stream.write(f"{key}={value}\n")


def check_services():
    if not (os.geteuid() == 0 and os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
            and platform.machine() == "aarch64"):
        raise RuntimeError("This fixture runs only on a disposable GitHub-hosted ARM64 VM")
    os.umask(0o077)
    # Exclusive creation prevents accidentally using or modifying existing service state.
    for state in (WEB_STATE.parent, KERNEL_STATE.parent, CONFIG):
        if state.exists():
            raise RuntimeError(f"Expected an unused staging path: {state}")
    CONFIG.mkdir(mode=0o755)
    CONFIG.chmod(0o755)
    bundles = CONFIG / "bundles"
    bundles.mkdir(mode=0o755)
    bundles.chmod(0o755)
    token = "stage-web." + secrets.token_hex(32)
    secret = secrets.token_hex(32)
    ws = Workspace()
    try:
        policy, kernel_env, ctx = write_signed_kernel_policy(
            ws.root, agents=[{"actor": "stage-web", "token": token, "allowed_tools": ["echo"]}],
            tools=["echo"], port=18765, audit_db=KERNEL_STATE,
        )
        shutil.copyfile(policy, CONFIG / "operator.json")
        shutil.chown(CONFIG / "operator.json", group="shards-stage-kernel")
        (CONFIG / "operator.json").chmod(0o440)
        verifier = CONFIG / "authority.hex"
        shutil.copyfile(ws.authority_public, verifier)
        verifier.chmod(0o444)
        assert verifier.stat().st_uid == 0
        for path in (CONFIG, verifier):
            assert subprocess.run(["/usr/sbin/runuser", "-u", "shards-stage-web", "--",
                                   "test", "-w", path]).returncode == 1
        env_file(CONFIG / "kernel.env", kernel_env)
        env_file(CONFIG / "origin.env", {
            "CF_ACCOUNT_ID": "0"*32, "CF_WORKERS_AI_TOKEN": "unused-test-only",
            "KERNEL_AUDIENCE": AUDIENCE, "STAGING_PUBLIC_ORIGIN": "https://" + PUBLIC_HOST,
            "SHARDS_KERNEL_AGENT_TOKEN": token, "SHARDS_EDGE_ASSERTION_SECRET": secret,
        })
        permit = CONFIG / "permit.json"
        source = issue_echo_permit(ws.root, ctx, text="arm64-stage", subject="stage-web")
        shutil.copyfile(source, permit)
        shutil.chown(permit, user="shards-stage-web")
        # The services receive only the public verifier, signed documents and role-specific secrets.
    finally:
        ws.close()

    def signed_headers():
        nonce, ts = secrets.token_hex(16), int(time.time() * 1000)
        sig = sign_assertion(secret.encode(), actor=ACTOR, nonce=nonce, ts_ms=ts)
        return {"X-Shards-Actor": ACTOR, "X-Forwarded-Host": PUBLIC_HOST,
                "X-Shards-Assertion": f"{nonce}.{ts}.{sig}"}

    try:
        subprocess.run(["systemctl", "start", *UNITS], check=True)
        ready()
        for port in (12026, 18765):
            listeners = subprocess.check_output(["ss", "-H", "-ltn", f"sport = :{port}"], text=True)
            assert [row.split()[3] for row in listeners.splitlines()] == [f"127.0.0.1:{port}"]
        for other, env, state in [("shards-stage-web", "kernel.env", KERNEL_STATE),
                                  ("shards-stage-kernel", "origin.env", WEB_STATE)]:
            for protected in (CONFIG / env, state):
                assert protected.is_file()
                assert subprocess.run(["runuser", "-u", other, "--", "test", "-r", protected]).returncode == 1
        used = signed_headers()
        status, cookie, page = request(12026, "/agent-os/", used)
        assert status == 200 and ACTOR.encode() in page and "Secure" in cookie
        code, receipt = call_kernel(token, permit)
        assert code == 0 and receipt["decision"] == "ALLOW" and receipt["result"] == "arm64-stage"

        allowed_request = receipt["request_id"]
        entries_before_restart = allowed_audit_entries(allowed_request)
        assert entries_before_restart
        old_pid = subprocess.check_output(
            ["systemctl", "show", UNITS[1], "-p", "MainPID", "--value"], text=True).strip()
        subprocess.run(["systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", UNITS[1]], check=True)
        ready()
        assert subprocess.check_output(
            ["systemctl", "show", UNITS[1], "-p", "MainPID", "--value"], text=True).strip() != old_pid
        subprocess.run(["systemctl", "restart", *UNITS], check=True)
        ready()
        status, _, page = request(12026, "/agent-os/", used)
        assert status == 403 and b"ASSERTION_REPLAYED" in page
        headers = {**signed_headers(), "Cookie": cookie.split(";", 1)[0]}
        status, new_cookie, _ = request(12026, "/agent-os/", headers)
        assert status == 200 and new_cookie is None
        code, receipt = call_kernel(token, permit)
        assert code == 2 and receipt["decision"] == "DENY"
        assert allowed_audit_entries(allowed_request) == entries_before_restart
        with sqlite3.connect(f"file:{WEB_STATE}?mode=ro", uri=True) as conn:
            assert conn.execute("select count(*) from agent_sessions").fetchone()[0] == 1
        print("ARM64 systemd PASS: loopback, role isolation, signed echo, crash recovery, persistent audit, session and replay")
    finally:
        subprocess.run(["systemctl", "stop", *reversed(UNITS)], check=True)


if __name__ == "__main__":
    check_services()
