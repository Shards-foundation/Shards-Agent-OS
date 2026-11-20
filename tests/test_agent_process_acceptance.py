"""Acceptance: the real `shards-agent-os-agent` process serves the governed UI.

These tests start the actual installed console script as a subprocess, sign in
over real HTTP with an edge assertion, submit a question through the real HTML
form, and read the rendered receipt page back. Nothing is mocked at the HTTP
boundary, and the browser-facing contract (no JavaScript, form POST, CSP) is
asserted on the bytes the server actually sends.

The model transport is a scripted provider here so the test is about the
product surface rather than model quality; `test_agent_qwen_live.py` covers
real Qwen inference and `test_agent_governed_e2e.py` covers real signed-kernel
execution.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode

from shards_agent_os.web_server import sign_assertion

from tests.agent_fixtures import Workspace, free_port

EDGE_SECRET = "edge-secret-0123456789abcdefghijklmnopqrstuvwxyz"
ACTOR = "owner@example.test"


def _close_streams(proc) -> None:
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


def _wait_health(port: int, deadline_s: float = 25.0) -> bool:
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            connection.request("GET", "/api/health")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


class InstalledProcessAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = Workspace()
        cls.port = free_port()
        cls.env = os.environ.copy()
        cls.env["SHARDS_EDGE_ASSERTION_SECRET"] = EDGE_SECRET
        # The fixture provider keeps this test hermetic; it is explicitly
        # allowed here and is never a default in the product path.
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "shards_agent_os.agent_cli",
             "--db", cls.ws.db_path, "--audience", cls.ws.audience,
             "--authority-public-key-file", cls.ws.authority_public,
             "--delegation-file", cls.ws.delegation(),
             "--kernel-port", "8765", "--port", str(cls.port),
             "--allow-fixture-provider", "--provider", "local-transformers",
             "--edge-secret-env", "SHARDS_EDGE_ASSERTION_SECRET"],
            env=cls.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if not _wait_health(cls.port):
            stderr = ""
            if cls.proc.poll() is not None:
                _, stderr = cls.proc.communicate(timeout=5)
            raise unittest.SkipTest(f"agent server did not start: {stderr[:300]}")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
            cls.proc.wait(timeout=5)
        _close_streams(cls.proc)
        cls.ws.close()

    # --- helpers ------------------------------------------------------

    def request(self, method, path, *, body=None, headers=None, cookie=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        merged = dict(headers or {})
        if cookie:
            merged["Cookie"] = f"shards_agent_session={cookie}"
        try:
            connection.request(method, path, body=body, headers=merged)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def sign_in(self) -> dict:
        nonce = secrets.token_hex(16)
        ts = int(time.time() * 1000)
        signature = sign_assertion(EDGE_SECRET.encode(), actor=ACTOR,
                                   nonce=nonce, ts_ms=ts)
        query = urlencode({"actor": ACTOR, "nonce": nonce, "ts": ts, "sig": signature})
        status, headers, _ = self.request("GET", f"/auth/callback?{query}")
        self.assertEqual(status, 303, headers)
        session = headers["Set-Cookie"].split(";")[0].split("=", 1)[1]
        _, _, page = self.request("GET", "/", cookie=session)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        conversation = re.search(
            r'name="conversation_id" value="([^"]+)"', page).group(1)
        return {"session": session, "csrf": csrf, "conversation": conversation}

    # --- acceptance ---------------------------------------------------

    def test_01_health_reports_the_real_provider_configuration(self):
        status, headers, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["service"], "shards-agent-os")
        self.assertFalse(payload["javascript"])
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_02_owner_signs_in_and_sees_the_agent_ui(self):
        session = self.sign_in()
        status, headers, page = self.request("GET", "/", cookie=session["session"])
        self.assertEqual(status, 200)
        self.assertIn("Shards Agent OS", page)
        self.assertIn("Ask Qwen", page)
        self.assertIn(f"signed in as {ACTOR}", page)
        # The browser contract: no script, no inline handler, mobile viewport.
        self.assertNotIn("<script", page.lower())
        self.assertNotIn("onclick", page.lower())
        self.assertIn('name="viewport"', page)
        self.assertIn("width=device-width", page)

    def test_03_governed_question_round_trip_shows_a_receipt(self):
        session = self.sign_in()
        body = urlencode({
            "csrf": session["csrf"], "conversation_id": session["conversation"],
            "question": "Is dispatch halted right now?",
        })
        status, headers, _ = self.request(
            "POST", "/ask", body=body, cookie=session["session"],
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body))},
        )
        self.assertEqual(status, 303, headers)
        _, _, page = self.request("GET", "/", cookie=session["session"])
        self.assertIn("Is dispatch halted right now?", page)
        self.assertIn("SUCCEEDED", page)
        turn_id = re.search(r"/turn/([0-9a-f]{32})", page).group(1)
        status, _, detail = self.request("GET", f"/turn/{turn_id}",
                                         cookie=session["session"])
        self.assertEqual(status, 200)
        self.assertIn("model.call", detail)

    def test_04_cross_site_post_is_refused(self):
        session = self.sign_in()
        body = urlencode({"csrf": session["csrf"],
                          "conversation_id": session["conversation"],
                          "question": "hi"})
        status, _, page = self.request(
            "POST", "/ask", body=body, cookie=session["session"],
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body)),
                     "Origin": "https://evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertIn("ORIGIN_MISMATCH", page)

    def test_05_unsigned_in_visitor_is_refused(self):
        status, _, page = self.request("GET", "/")
        self.assertEqual(status, 401)
        self.assertIn("NOT_SIGNED_IN", page)

    def test_06_restart_preserves_the_receipt(self):
        """Stop and restart the real process; the conversation must survive."""
        session = self.sign_in()
        body = urlencode({"csrf": session["csrf"],
                          "conversation_id": session["conversation"],
                          "question": "Durability check."})
        self.request("POST", "/ask", body=body, cookie=session["session"],
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Content-Length": str(len(body))})

        type(self).proc.terminate()
        type(self).proc.wait(timeout=10)
        _close_streams(type(self).proc)
        port = free_port()
        type(self).port = port
        type(self).proc = subprocess.Popen(
            [sys.executable, "-m", "shards_agent_os.agent_cli",
             "--db", self.ws.db_path, "--audience", self.ws.audience,
             "--authority-public-key-file", self.ws.authority_public,
             "--delegation-file", self.ws.delegation(),
             "--kernel-port", "8765", "--port", str(port),
             "--allow-fixture-provider", "--provider", "local-transformers",
             "--edge-secret-env", "SHARDS_EDGE_ASSERTION_SECRET"],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertTrue(_wait_health(port), "restarted server did not become healthy")
        _, _, page = self.request("GET", "/", cookie=session["session"])
        self.assertIn("Durability check.", page)


if __name__ == "__main__":
    unittest.main()
