#!/usr/bin/env python3
"""Report non-secret Oracle staging prerequisites, using read-only local observations."""
import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
from importlib.metadata import distributions
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener


def output(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def present(path):
    try:
        Path(path).stat()
        return True
    except FileNotFoundError:
        return False
    except PermissionError:
        return None


def instance_fields():
    # OCI IMDSv2, field-specific requests only. Ignore operator proxy settings.
    opener = build_opener(ProxyHandler({}))
    fields = {}
    for field in ("displayName", "region", "shape"):
        request = Request("http://169.254.169.254/opc/v2/instance/" + field,
                          headers={"Authorization": "Bearer Oracle"})
        try:
            with opener.open(request, timeout=1) as response:
                fields[field] = response.read(256).decode().strip()
        except (OSError, ValueError):
            fields[field] = None
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oci", action="store_true", help="Read instance name, region and shape via IMDSv2")
    parser.add_argument("--expected-host", help="Compare the hostname to the operator inventory")
    parser.add_argument("--pilot-db", help="Check the historical monitor database by file metadata only")
    args = parser.parse_args()
    # Never include peer addresses, environment contents, journal text or credential files.
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("MemTotal", "MemAvailable"):
            mem[key] = int(value.split()[0]) // 1024
    units = {}
    for name in ("shards-github-monitor", "shards-stage-kernel", "shards-stage-origin"):
        units[name] = output("systemctl", "show", f"{name}.service",
                             "-p", "LoadState", "-p", "ActiveState", "-p", "UnitFileState")
    runners = output("systemctl", "list-units", "--type=service", "--state=active",
                     "--no-legend", "--plain", "actions.runner.*")
    listeners = output("ss", "-H", "-ltn")
    ports = {}
    for port in (8765, 12000, 18765, 12026):
        if listeners is None:
            ports[port] = None
            continue
        local = [line.split()[3] for line in listeners.splitlines() if len(line.split()) >= 5]
        hosts = [addr.rsplit(":", 1)[0] for addr in local if addr.endswith(f":{port}")]
        ports[port] = ["loopback" if host in ("127.0.0.1", "[::1]") else "non-loopback"
                       for host in hosts]
    libraries = Path("/opt/shards-agent-stage/venv/lib").glob("python*/site-packages")
    packages = distributions(path=[str(lib) for lib in libraries])
    kernel_version = next((pkg.version for pkg in packages
                           if pkg.metadata.get("Name") == "shards-kernel"), None)
    print(json.dumps({
        "expected_hostname_matches": socket.gethostname().split(".")[0] == args.expected_host
                                     if args.expected_host else None,
        "oci_instance": instance_fields() if args.oci else None,
        "os": platform.freedesktop_os_release().get("PRETTY_NAME"), "arch": platform.machine(),
        "linux_release": platform.release(), "logical_cpus": os.cpu_count(), "memory_mib": mem,
        "var_lib_free_gib": round(shutil.disk_usage("/var/lib").free / 2**30, 1),
        "var_lib_fstype": output("findmnt", "-n", "-o", "FSTYPE", "-T", "/var/lib"),
        "active_runner_units": None if runners is None else len(runners.splitlines()),
        "units": units, "tcp_listeners": ports, "historical_pilot_db_present": present(args.pilot_db) if args.pilot_db else None,
        "staging_kernel_version": kernel_version,
    }, indent=2))


if __name__ == "__main__":
    main()
