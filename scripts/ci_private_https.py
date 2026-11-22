"""Disposable TLS and reverse-proxy acceptance. Uses a recording HTTP fixture only."""
import argparse
import contextlib
import http.client
import http.server
import os
from pathlib import Path
import pwd
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from unittest.mock import patch

from deploy.oracle.https import manage as tls


def request(context, method, path, *, name=tls.NAME, host=tls.NAME, headers=(), body=b""):
    with socket.create_connection(("127.0.0.1", 18443), timeout=3) as sock, context.wrap_socket(sock, server_hostname=name) as conn:
        fields = dict(headers, Host=host, Connection="close")
        msg = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items())
        conn.sendall((msg + f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
        with http.client.HTTPResponse(conn, method=method) as response:
            response.begin()
            return response.status, response.getheaders(), response.read()


def exercise(context):
    assert request(context, "GET", "/")[0] == 404
    status, headers, _ = request(context, "GET", "/agent-os/")
    assert status == 503 and dict(headers)["X-Shards-Stage-TLS"] == "1"
    assert request(context, "GET", "/agent-os/", host="other.example")[0] == 421
    for client, name in ((ssl.create_default_context(), tls.NAME), (context, "wrong.example")):
        try:
            request(client, "GET", "/", name=name)
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError("Expected TLS verification refusal")

    calls = []

    class Recorder(http.server.BaseHTTPRequestHandler):
        def accept_request(self):
            calls.append((self.command, self.path, self.headers, self.rfile.read(int(self.headers.get("Content-Length", 0)))))
            self.send_response(303)
            self.send_header("Location", "/agent-os/turn/" + "a"*32)
            self.send_header("Set-Cookie", "shards_agent_session=fixture; Path=/agent-os/; HttpOnly; Secure")
            self.send_header("Set-Cookie", "expired=; Max-Age=0; Secure")
            self.end_headers()
        do_POST = do_GET = do_HEAD = accept_request

        def log_message(self, *args):
            pass

    with http.server.HTTPServer(("127.0.0.1", 12026), Recorder) as app:
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        try:
            headers = {"Origin": "https://agentos-stage.shardsinc.co.uk", "X-Forwarded-Host": "agentos-stage.shardsinc.co.uk",
                       "X-Shards-Actor": "actor@example.test", "X-Shards-Assertion": "fixture.assertion",
                       "Cookie": "shards_agent_session=fixture", "Content-Type": "application/x-www-form-urlencoded"}
            for method, path in (("POST", "/agent-os/ask?v=1"), ("POST", "/agent-os/logout"),
                                 ("GET", "/agent-os/"), ("HEAD", "/agent-os/turn/" + "a"*32)):
                body = b"message=fixture" if method == "POST" else b""
                status, response, _ = request(context, method, path, headers=headers, body=body)
                assert status == 303 and dict(response)["Location"] == "/agent-os/turn/" + "a"*32
                assert [value for key, value in response if key.lower() == "set-cookie"] == [
                    "shards_agent_session=fixture; Path=/agent-os/; HttpOnly; Secure", "expired=; Max-Age=0; Secure"]
                actual_method, actual_path, actual_headers, actual_body = calls[-1]
                assert (method, path, body) == (actual_method, actual_path, actual_body)
                for key, value in headers.items():
                    assert actual_headers.get_all(key) == [value], key
            for path in ("/agent-os", "/health", "/agent-os/api/health", "/agent-os/ask"):
                assert request(context, "GET", path)[0] == 404
            assert len(calls) == 4
        finally:
            app.shutdown()
            thread.join()


def run(systemd):
    assert os.geteuid() == 0
    if systemd:
        assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.uname().machine == "aarch64"
    else:
        assert Path("/.dockerenv").exists()
    assert not any(os.path.lexists(path) for path in (tls.ETC, tls.UNIT_FILE, Path("/etc/shards-agent-stage")))
    assert not any(tls.listeners(port) for port in (12026, 18443, 18765))
    with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
        root = Path(tmp)
        ca = root / "fixture-ca.pem"
        cakey = root / "fixture-ca.key"
        creds = root / "credentials"
        run_dir = root / "runtime"
        run_dir.mkdir()
        if not systemd:
            stack.enter_context(patch.object(tls, "ETC", creds))
        stack.enter_context(patch.object(tls, "ROOT_CA", ca))
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink):
            tls.make_csr()
            tls.make_csr()
        key = tls.ETC / "tls.key"
        leaf = tls.ETC / "leaf.pem"
        tls.output("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                   "-keyout", cakey, "-out", ca, "-days", "1", "-subj", "/CN=Ephemeral TLS test CA")
        extensions = root / "extensions"
        extensions.write_text("subjectAltName=DNS:" + tls.NAME + "\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
        tls.output("openssl", "x509", "-req", "-in", tls.ETC / "origin.csr", "-CA", ca, "-CAkey", cakey,
                   "-CAcreateserial", "-out", leaf, "-days", "1", "-extfile", extensions)
        leaf.chmod(0o644)
        tls.validate_cert(leaf)
        if systemd:
            # This disposable VM has no cloudflared connector or Agent OS units.
            # Install real systemd/LoadCredential artifacts; exercise transport separately.
            with patch.object(tls, "preflight"):
                stack.callback(tls.rollback)
                tls.install(tls.owned_unit())
                tls.install(tls.owned_unit())
            info = tls.owned_unit()
            assert info["ActiveState"] == "active"
            rows = tls.listeners(18443)
            assert len(rows) == 1 and rows[0].split()[3] == "127.0.0.1:18443" and f"pid={info['MainPID']}," in rows[0]
        else:
            nobody = pwd.getpwnam("nobody")
            root.chmod(0o711)
            os.chown(run_dir, nobody.pw_uid, nobody.pw_gid)
            os.chown(key, nobody.pw_uid, nobody.pw_gid)
            proc = subprocess.Popen(["/usr/sbin/apache2", "-d", run_dir, "-f", tls.SRC / "httpd.conf", "-DFOREGROUND"],
                    env={**os.environ, "RUNTIME_DIRECTORY": str(run_dir), "CREDENTIALS_DIRECTORY": str(creds)},
                    user=nobody.pw_uid, group=nobody.pw_gid, extra_groups=[])
            stack.callback(proc.wait, 5)
            stack.callback(proc.terminate)
            for _ in range(50):
                if tls.listeners(18443):
                    break
                assert proc.poll() is None, "TLS daemon exited"
                time.sleep(0.1)
        exercise(ssl.create_default_context(cafile=str(ca)))
        if systemd:
            tls.rollback()
            tls.rollback()
            assert not tls.listeners(18443) and not tls.UNIT_FILE.exists() and key.exists()
    print("PASS: verified TLS, four allowed routes, headers, cookies, redirects, and stopped upstream.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--systemd", action="store_true")
    run(parser.parse_args().systemd)
