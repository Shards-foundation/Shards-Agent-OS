"""Manage only the Oracle staging TLS listener. Use from an administrator-controlled checkout."""
import argparse
import fcntl
import hashlib
import http.client
import os
import platform
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NAME = "agentos-origin-stage.shardsinc.co.uk"
UNIT = "shards-stage-https.service"
ETC = Path("/etc/shards-stage-https")
SRC = Path(__file__).resolve().parent
UNIT_FILE = Path("/etc/systemd/system") / UNIT
ROOT_CA = SRC / "origin-ca-ecc.pem"
ROOT_DIGEST = "aa63697a22764b67b2134ce14cb5690ea336940b93986113f49545917832d80d"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def output(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout


def regular(path, mode):
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == mode,
         f"Unexpected type, owner or mode on {path.name}")


def publish(path, content, mode):
    if os.path.lexists(path):
        regular(path, mode)
        need(path.read_bytes() == content, f"Conflicting {path.name}")
        return
    with tempfile.NamedTemporaryFile(dir=path.parent) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fchmod(tmp.fileno(), mode)
        os.fsync(tmp.fileno())
        os.link(tmp.name, path)


def properties(unit, *keys):
    proc = subprocess.run(["systemctl", "show", unit, *(f"--property={key}" for key in keys)],
                          capture_output=True, text=True)
    need(proc.returncode in (0, 4), f"Cannot inspect {unit}")
    return dict(line.split("=", 1) for line in proc.stdout.splitlines())


def owned_unit():
    props = properties(UNIT, "LoadState", "FragmentPath", "DropInPaths", "ActiveState", "MainPID", "NeedDaemonReload")
    need(props.get("NeedDaemonReload") != "yes", "Systemd has stale HTTPS unit state")
    need(not props.get("DropInPaths") and props.get("FragmentPath") in ("", str(UNIT_FILE)),
         "HTTPS unit has conflicting systemd configuration")
    if os.path.lexists(UNIT_FILE):
        regular(UNIT_FILE, 0o644)
        need(UNIT_FILE.read_bytes() == (SRC / UNIT).read_bytes(), "HTTPS unit differs from reviewed definition")
    else:
        need(props.get("LoadState") == "not-found", "Unexpected installed HTTPS unit")
    return props


def listeners(port):
    return output("ss", "-H", "-ltnp", "sport", "=", f":{port}").decode().splitlines()


def check_tunnel():
    unit = "shards-stage-tunnel.service"
    props = properties(unit, "ActiveState", "MainPID", "InvocationID")
    pid = props.get("MainPID", "")
    need(props.get("ActiveState") == "active" and pid.isdecimal() and int(pid) > 1, "Tunnel unit is inactive")
    proc = Path("/proc") / pid
    need(os.path.samefile(proc / "ns/net", "/proc/self/ns/net"),
         "Connector does not share host loopback")
    need(Path(os.readlink(proc / "exe")).name == "cloudflared", "Unexpected tunnel executable")
    binary = (proc / "exe").stat()
    need(stat.S_ISREG(binary.st_mode) and binary.st_uid == 0 and not binary.st_mode & 0o022,
         "Expected an administrator-owned connector binary")
    version = re.search(rb"cloudflared version (\d+)\.(\d+)\.(\d+)", output(proc / "exe", "--version"))
    need(version and tuple(map(int, version.groups())) >= (2025, 7, 0), "Workers VPC needs cloudflared >= 2025.7.0")
    invocation = props.get("InvocationID", "")
    need(re.fullmatch("[0-9a-f]{32}", invocation), "Tunnel invocation unavailable")
    # Never emit the journal or argv. The latest registration per connection
    # index in this invocation provides transport evidence without its token.
    journal = output("journalctl", "-b", "--no-pager", "-o", "cat", "-n", "128",
                     "--grep=Registered tunnel connection", "_SYSTEMD_INVOCATION_ID=" + invocation)
    transports = {}
    for line in journal.splitlines():
        index = re.search(rb'\bconnIndex"?[=:]"?(\d+)', line)
        proto = re.search(rb'\bprotocol"?[=:]"?(quic|http2)\b', line)
        if index and proto:
            transports[index[1]] = proto[1]
    need(transports and set(transports.values()) == {b"quic"},
         "Cannot confirm QUIC registrations for this tunnel invocation; inspect connector transport privately")
    print("Tunnel shares loopback; supported cloudflared and QUIC registration verified.")


def preflight():
    osinfo = platform.freedesktop_os_release()
    need(osinfo.get("ID") == "ubuntu" and osinfo.get("VERSION_ID") == "24.04" and platform.machine() == "aarch64",
         "Expected Ubuntu 24.04 ARM64")
    check_tunnel()
    for unit, port in (("shards-stage-kernel.service", 18765), ("shards-stage-origin.service", 12026)):
        props = properties(unit, "LoadState", "ActiveState")
        need(props == {"LoadState": "loaded", "ActiveState": "inactive"} and not listeners(port),
             f"Expected stopped {unit} and unused port {port}")
    unit = owned_unit()
    rows = listeners(18443)
    if unit.get("ActiveState") == "active":
        need(len(rows) == 1 and rows[0].split()[3] == "127.0.0.1:18443"
             and f"pid={unit['MainPID']}," in rows[0], "Unexpected HTTPS listener or owner")
    else:
        need(unit.get("ActiveState") == "inactive" and not rows, "HTTPS unit or port 18443 is busy")
    if os.path.lexists(ETC):
        meta = ETC.lstat()
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o755,
             "Unexpected TLS configuration directory")
    der = output("openssl", "x509", "-in", ROOT_CA, "-outform", "DER")
    need(hashlib.sha256(der).hexdigest() == ROOT_DIGEST, "Unexpected Origin ECC CA pin")
    print("Preflight passed. Application ports closed. apache2-bin " +
          ("present." if Path("/usr/sbin/apache2").exists() else "required before install."))
    return unit


def make_csr():
    if not ETC.exists():
        ETC.mkdir(mode=0o755)
        ETC.chmod(0o755)
    key, csr = ETC / "tls.key", ETC / "origin.csr"
    if not os.path.lexists(key):
        need(not any(ETC.iterdir()), "TLS directory already contains files but has no key")
        # OpenSSL writes the private key directly to a private file on Oracle.
        with tempfile.NamedTemporaryFile(dir=ETC) as tmp:
            output("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", tmp.name)
            os.fsync(tmp.fileno())
            os.link(tmp.name, key)
    regular(key, 0o600)
    if not os.path.lexists(csr):
        publish(csr, output("openssl", "req", "-new", "-sha256", "-key", key, "-subj", "/CN=" + NAME,
                            "-addext", "subjectAltName=DNS:" + NAME), 0o644)
    regular(csr, 0o644)
    output("openssl", "req", "-in", csr, "-noout", "-verify")
    description = output("openssl", "req", "-in", csr, "-text", "-noout").decode()
    need(re.search(r"X509v3 Subject Alternative Name:\s*\n\s*DNS:" + re.escape(NAME) + r"\s*\n", description),
         "CSR has an unexpected SAN")
    need(output("openssl", "req", "-in", csr, "-pubkey", "-noout") == output("openssl", "pkey", "-in", key, "-pubout"),
         "CSR and host key differ")
    # Serialize just the validated public CSR, even if an input file has trailing data.
    print(output("openssl", "req", "-in", csr, "-outform", "PEM").decode().strip())


def validate_cert(path):
    regular(ETC / "tls.key", 0o600)
    output("openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", ROOT_CA,
           "-purpose", "sslserver", "-verify_hostname", NAME, path)
    san = output("openssl", "x509", "-in", path, "-noout", "-ext", "subjectAltName").decode().splitlines()
    need(len(san) == 2 and san[1].strip() == "DNS:" + NAME, "Certificate requires exactly the private DNS SAN")
    need(output("openssl", "x509", "-in", path, "-pubkey", "-noout") ==
         output("openssl", "pkey", "-in", ETC / "tls.key", "-pubout"), "Certificate does not match Oracle key")


def import_leaf():
    leaf = ETC / "leaf.pem"
    if os.path.lexists(leaf):
        regular(leaf, 0o644)
        validate_cert(leaf)
        return
    print("Paste the PUBLIC Origin ECC certificate including its BEGIN and END lines:", flush=True)
    lines = []
    for _ in range(64):
        line = sys.stdin.buffer.readline(256).strip()
        if line == b"-----END CERTIFICATE-----" and lines:
            lines.append(line)
            break
        need(line == b"-----BEGIN CERTIFICATE-----" if not lines else re.fullmatch(rb"[A-Za-z0-9+/=]{1,128}", line),
             "Expected one PEM certificate")
        lines.append(line)
    else:
        raise ValueError("Incomplete certificate")
    pem = b"\n".join(lines) + b"\n"
    with tempfile.NamedTemporaryFile(dir=ETC) as tmp:
        tmp.write(pem)
        tmp.flush()
        validate_cert(tmp.name)
    publish(leaf, pem, 0o644)


def probe(path):
    ctx = ssl.create_default_context(cafile=str(ROOT_CA))
    with socket.create_connection(("127.0.0.1", 18443), timeout=4) as sock, ctx.wrap_socket(sock, server_hostname=NAME) as tls:
        leaf = ssl.PEM_cert_to_DER_cert((ETC / "leaf.pem").read_text())
        need(tls.getpeercert(binary_form=True) == leaf, "Unexpected served certificate")
        tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {NAME}\r\nConnection: close\r\n\r\n".encode())
        with http.client.HTTPResponse(tls) as response:
            response.begin()
            need(response.getheader("X-Shards-Stage-TLS") == "1", "Missing TLS listener response marker")
            return response.status


def verify():
    need(probe("/") == 404 and probe("/agent-os/") == 503, "Expected local TLS 404 and stopped-upstream 503")
    print("HTTPS verified: full chain and hostname, outside mount 404, stopped origin 503.")


def install(previous):
    need(Path("/usr/sbin/apache2").is_file(), "Install the Ubuntu apache2-bin package first")
    regular(ETC / "tls.key", 0o600)
    import_leaf()
    publish(ETC / "httpd.conf", (SRC / "httpd.conf").read_bytes(), 0o644)
    publish(UNIT_FILE, (SRC / UNIT).read_bytes(), 0o644)
    output("systemd-analyze", "verify", UNIT_FILE)
    output("systemctl", "daemon-reload")
    owned_unit()
    started = previous.get("ActiveState") != "active"
    try:
        if started:
            output("systemctl", "start", UNIT)
        for attempt in range(30):
            try:
                verify()
                break
            except ConnectionRefusedError:
                if attempt == 29:
                    raise
                time.sleep(0.1)
        preflight()
        output("systemctl", "enable", UNIT)
    except BaseException:
        if started:
            output("systemctl", "stop", UNIT)
        raise


def rollback():
    owned_unit()
    if os.path.lexists(UNIT_FILE):
        output("systemctl", "disable", "--now", UNIT)
        UNIT_FILE.unlink()
        output("systemctl", "daemon-reload")
    print("Dedicated unit removed. TLS materials retained for reinstall.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "csr", "install", "verify", "rollback"))
    action = parser.parse_args().action
    need(os.geteuid() == 0, "Run from the staging administrator session")
    os.umask(0o077)
    # Serialize changes by this helper. The descriptor is closed at process exit.
    if action in {"csr", "install", "rollback"}:
        lock = os.open("/run/shards-stage-https.lock", os.O_CLOEXEC | os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if action == "rollback":
        rollback()
        return
    previous = preflight()
    if action == "csr":
        make_csr()
    elif action == "install":
        install(previous)
    elif action == "verify":
        verify()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        # Do not print argv, certificate input, process status or journals.
        sys.exit(f"STOP: {Path(exc.cmd[0]).name} failed (exit {exc.returncode}).")
    except (OSError, ValueError) as exc:
        sys.exit(f"STOP: {exc}")
