"""Web surface: identity, session, CSRF/origin/Host gating, budgets, no-JS page."""
from __future__ import annotations

import http.client
import json
import secrets
import threading
import time
import unittest
from urllib.parse import urlencode

from shards_agent_os import agent_state
from shards_agent_os.web_server import (
    CSP, WebConfig, WebError, _create_session, make_server, sign_assertion,
)

from tests.agent_fixtures import (
    ACTOR, AUDIENCE, ScriptedProvider, Workspace, decision, free_port,
)

EDGE_SECRET = b"edge-secret-0123456789abcdefghijklmnop"


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.provider = ScriptedProvider(decision("Dispatch is not halted."))
        self.port = free_port()
        self.config = WebConfig(
            db_path=self.ws.db_path, audience=AUDIENCE, provider=self.provider,
            authority=self.ws.authority(delegation_file=self.ws.delegation()),
            kernel_port=8765, edge_secret=EDGE_SECRET,
            host="127.0.0.1", port=self.port,
        )
        self.server = make_server(self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self._wait_ready()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.ws.close()

    def _wait_ready(self):
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                status, _, _ = self.request("GET", "/api/health")
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.02)
        raise RuntimeError("server did not start")

    def request(self, method, path, *, body=None, headers=None, session=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        merged = dict(headers or {})
        if session:
            merged["Cookie"] = f"shards_agent_session={session['session_id']}"
        try:
            connection.request(method, path, body=body, headers=merged)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def sign_in(self, actor: str = ACTOR) -> dict:
        nonce = "nonce-" + secrets.token_hex(12)
        ts = int(time.time() * 1000)
        signature = sign_assertion(EDGE_SECRET, actor=actor, nonce=nonce, ts_ms=ts)
        query = urlencode({"actor": actor, "nonce": nonce, "ts": ts, "sig": signature})
        status, headers, _ = self.request("GET", f"/auth/callback?{query}")
        self.assertEqual(status, 303, headers)
        cookie = headers["Set-Cookie"]
        session_id = cookie.split(";")[0].split("=", 1)[1]
        session = {"session_id": session_id}
        status, _, page = self.request("GET", "/", session=session)
        self.assertEqual(status, 200)
        import re

        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        session["csrf"] = csrf
        return session

    def ask(self, session, question, *, conversation_id=None):
        if conversation_id is None:
            status, _, page = self.request("GET", "/", session=session)
            conversation_id = __import__("re").search(
                r'name="conversation_id" value="([^"]+)"', page
            ).group(1)
        body = urlencode({
            "csrf": session["csrf"], "conversation_id": conversation_id,
            "question": question,
        })
        return self.request(
            "POST", "/ask", body=body, session=session,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body))},
        )


class HealthAndPageTests(ServerTestCase):
    def test_health_reports_provider_without_secrets(self):
        status, headers, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["provider"], "scripted")
        self.assertFalse(payload["javascript"])
        self.assertEqual(headers["Content-Security-Policy"], CSP)

    def test_page_contains_no_javascript_at_all(self):
        session = self.sign_in()
        _, headers, page = self.request("GET", "/", session=session)
        self.assertNotIn("<script", page.lower())
        self.assertNotIn("javascript:", page.lower())
        self.assertNotIn("onclick", page.lower())
        self.assertNotIn("onload", page.lower())
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-eval", headers["Content-Security-Policy"])

    def test_security_headers_present(self):
        _, headers, _ = self.request("GET", "/api/health")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_unauthenticated_read_is_refused(self):
        status, _, body = self.request("GET", "/")
        self.assertEqual(status, 401)
        self.assertIn("NOT_SIGNED_IN", body)

    def test_unknown_path_is_404(self):
        session = self.sign_in()
        status, _, _ = self.request("GET", "/admin/secrets", session=session)
        self.assertEqual(status, 404)

    def test_page_is_mobile_first(self):
        session = self.sign_in()
        _, _, page = self.request("GET", "/", session=session)
        self.assertIn('name="viewport"', page)
        self.assertIn("width=device-width", page)
        self.assertIn("prefers-color-scheme", page)


class IdentityTests(ServerTestCase):
    def test_assertion_with_a_bad_signature_is_refused(self):
        ts = int(time.time() * 1000)
        query = urlencode({"actor": ACTOR, "nonce": "nonce-1234567890abc",
                           "ts": ts, "sig": "0" * 64})
        status, _, body = self.request("GET", f"/auth/callback?{query}")
        self.assertEqual(status, 403)
        self.assertIn("ASSERTION_INVALID", body)

    def test_expired_assertion_is_refused(self):
        old = int(time.time() * 1000) - 600_000
        nonce = "nonce-1234567890abc"
        signature = sign_assertion(EDGE_SECRET, actor=ACTOR, nonce=nonce, ts_ms=old)
        query = urlencode({"actor": ACTOR, "nonce": nonce, "ts": old, "sig": signature})
        status, _, body = self.request("GET", f"/auth/callback?{query}")
        self.assertEqual(status, 403)
        self.assertIn("ASSERTION_EXPIRED", body)

    def test_assertion_cannot_be_redirected_to_another_actor(self):
        ts = int(time.time() * 1000)
        nonce = "nonce-1234567890abc"
        signature = sign_assertion(EDGE_SECRET, actor=ACTOR, nonce=nonce, ts_ms=ts)
        query = urlencode({"actor": "attacker@example.test", "nonce": nonce,
                           "ts": ts, "sig": signature})
        status, _, body = self.request("GET", f"/auth/callback?{query}")
        self.assertEqual(status, 403)
        self.assertIn("ASSERTION_INVALID", body)

    def test_json_exchange_issues_a_session(self):
        ts = int(time.time() * 1000)
        nonce = "nonce-abcdef1234567890"
        body = json.dumps({
            "actor": ACTOR, "nonce": nonce, "ts": ts,
            "sig": sign_assertion(EDGE_SECRET, actor=ACTOR, nonce=nonce, ts_ms=ts),
        })
        status, _, payload = self.request(
            "POST", "/auth/exchange", body=body,
            headers={"Content-Type": "application/json",
                     "Content-Length": str(len(body))},
        )
        self.assertEqual(status, 200)
        data = json.loads(payload)
        self.assertRegex(data["session"], r"^[0-9a-f]{32}$")
        self.assertGreaterEqual(len(data["csrf"]), 32)

    def test_session_cookie_is_httponly_and_samesite_strict(self):
        ts = int(time.time() * 1000)
        nonce = "nonce-abcdef1234567890"
        query = urlencode({
            "actor": ACTOR, "nonce": nonce, "ts": ts,
            "sig": sign_assertion(EDGE_SECRET, actor=ACTOR, nonce=nonce, ts_ms=ts),
        })
        _, headers, _ = self.request("GET", f"/auth/callback?{query}")
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Max-Age=28800", cookie)
        self.assertNotIn("{SESSION_TTL_MS", cookie)
        self.assertNotIn("edge", cookie.lower())
        self.assertNotIn("token", cookie.lower())

    def test_session_cannot_be_forged(self):
        status, _, _ = self.request(
            "GET", "/", session={"session_id": "0" * 32},
        )
        self.assertEqual(status, 401)

    def test_logout_clears_the_session(self):
        session = self.sign_in()
        body = urlencode({"csrf": session["csrf"]})
        status, headers, _ = self.request(
            "POST", "/logout", body=body, session=session,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body))},
        )
        self.assertEqual(status, 303)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        status, _, _ = self.request("GET", "/", session=session)
        self.assertEqual(status, 401)


class AssertionReplayTests(ServerTestCase):
    def test_callback_assertion_is_single_use(self):
        ts = int(time.time() * 1000)
        nonce = "nonce-" + secrets.token_hex(12)
        signature = sign_assertion(EDGE_SECRET, actor=ACTOR, nonce=nonce, ts_ms=ts)
        query = urlencode({"actor": ACTOR, "nonce": nonce, "ts": ts, "sig": signature})
        self.assertEqual(self.request("GET", f"/auth/callback?{query}")[0], 303)
        status, _, body = self.request("GET", f"/auth/callback?{query}")
        self.assertEqual(status, 403)
        self.assertIn("ASSERTION_REPLAYED", body)

    def test_json_exchange_assertion_is_single_use(self):
        ts = int(time.time() * 1000)
        nonce = "nonce-" + secrets.token_hex(12)
        body = json.dumps({"actor": ACTOR, "nonce": nonce, "ts": ts,
                           "sig": sign_assertion(
                               EDGE_SECRET, actor=ACTOR, nonce=nonce, ts_ms=ts)})
        headers = {"Content-Type": "application/json",
                   "Content-Length": str(len(body))}
        self.assertEqual(self.request("POST", "/auth/exchange", body=body,
                                      headers=headers)[0], 200)
        status, _, response = self.request("POST", "/auth/exchange",
                                           body=body, headers=headers)
        self.assertEqual(status, 403)
        self.assertIn("ASSERTION_REPLAYED", response)


class EdgeProxyTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.config.edge_public_origin = "https://agents.shardsinc.co.uk"

    def edge_headers(self, actor=ACTOR, nonce=None):
        nonce = nonce or "nonce-" + secrets.token_hex(12)
        ts = int(time.time() * 1000)
        return {
            "Host": "origin.internal.example",
            "X-Forwarded-Host": "agents.shardsinc.co.uk",
            "X-Shards-Actor": actor,
            "X-Shards-Assertion": (
                f"{nonce}.{ts}."
                f"{sign_assertion(EDGE_SECRET, actor=actor, nonce=nonce, ts_ms=ts)}"
            ),
        }

    def test_edge_signed_get_bootstraps_session(self):
        status, headers, page = self.request(
            "GET", "/", headers=self.edge_headers(),
        )
        self.assertEqual(status, 200)
        self.assertIn("signed in as", page)
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Max-Age=28800", cookie)

    def test_edge_state_is_reset_on_one_keepalive_connection(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            conn.request("GET", "/", headers=self.edge_headers(actor=ACTOR))
            first = conn.getresponse()
            first_body = first.read().decode()
            first_cookie = first.getheader("Set-Cookie")
            self.assertEqual(first.status, 200)
            self.assertIn(ACTOR, first_body)
            self.assertIsNotNone(first_cookie)

            # The same socket must not inherit the previous request's cookie.
            conn.request("GET", "/api/health")
            health = conn.getresponse()
            health.read()
            self.assertEqual(health.status, 200)
            self.assertIsNone(health.getheader("Set-Cookie"))

            # Nor may the next actor inherit the first actor's signed claim.
            second_actor = "other@example.test"
            conn.request("GET", "/", headers=self.edge_headers(actor=second_actor))
            second = conn.getresponse()
            second_body = second.read().decode()
            second_cookie = second.getheader("Set-Cookie")
            self.assertEqual(second.status, 200)
            self.assertIn(second_actor, second_body)
            self.assertNotIn(ACTOR, second_body)
            self.assertIsNotNone(second_cookie)
            self.assertNotEqual(first_cookie, second_cookie)
        finally:
            conn.close()

    def test_edge_actor_mismatch_rejects_existing_cookie(self):
        session = self.sign_in()
        headers = self.edge_headers(actor="attacker@example.test")
        status, _, body = self.request("GET", "/", session=session, headers=headers)
        self.assertEqual(status, 403)
        self.assertIn("EDGE_ACTOR_MISMATCH", body)

    def test_edge_assertion_replay_is_refused(self):
        headers = self.edge_headers()
        self.assertEqual(self.request("GET", "/", headers=headers)[0], 200)
        status, _, body = self.request("GET", "/", headers=headers)
        self.assertEqual(status, 403)
        self.assertIn("ASSERTION_REPLAYED", body)

    def test_edge_bogus_signature_is_refused(self):
        headers = self.edge_headers()
        nonce, ts, _ = headers["X-Shards-Assertion"].split(".")
        headers["X-Shards-Assertion"] = f"{nonce}.{ts}.{'0' * 64}"
        status, _, body = self.request("GET", "/", headers=headers)
        self.assertEqual(status, 403)
        self.assertIn("ASSERTION_INVALID", body)

    def test_edge_requires_explicit_trusted_public_origin(self):
        self.config.edge_public_origin = None
        status, _, body = self.request("GET", "/", headers=self.edge_headers())
        self.assertEqual(status, 403)
        self.assertIn("EDGE_NOT_CONFIGURED", body)

    def test_edge_rejects_unexpected_forwarded_host(self):
        headers = self.edge_headers()
        headers["X-Forwarded-Host"] = "evil.example"
        status, _, body = self.request("GET", "/", headers=headers)
        self.assertEqual(status, 403)
        self.assertIn("EDGE_HOST_INVALID", body)

    def test_edge_enforces_browser_origin_on_write(self):
        session = self.sign_in()
        body = urlencode({"csrf": session["csrf"], "conversation_id": "0" * 32,
                          "question": "test"})
        headers = self.edge_headers()
        headers["Origin"] = "https://evil.example"
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
        status, _, page = self.request(
            "POST", "/ask", body=body, headers=headers, session=session,
        )
        self.assertEqual(status, 403)
        self.assertIn("ORIGIN_MISMATCH", page)


class CsrfAndOriginTests(ServerTestCase):
    def test_ask_without_csrf_is_refused(self):
        session = self.sign_in()
        body = urlencode({"csrf": "wrong", "conversation_id": "0" * 32, "question": "hi"})
        status, _, page = self.request(
            "POST", "/ask", body=body, session=session,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body))},
        )
        self.assertEqual(status, 403)
        self.assertIn("CSRF_INVALID", page)

    def test_ask_with_a_cross_origin_origin_header_is_refused(self):
        session = self.sign_in()
        body = urlencode({"csrf": session["csrf"], "conversation_id": "0" * 32,
                          "question": "hi"})
        status, _, page = self.request(
            "POST", "/ask", body=body, session=session,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body)),
                     "Origin": "https://evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertIn("ORIGIN_MISMATCH", page)

    def test_ask_with_a_cross_origin_referer_is_refused(self):
        session = self.sign_in()
        body = urlencode({"csrf": session["csrf"], "conversation_id": "0" * 32,
                          "question": "hi"})
        status, _, page = self.request(
            "POST", "/ask", body=body, session=session,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body)),
                     "Referer": "https://evil.example/page"},
        )
        self.assertEqual(status, 403)
        self.assertIn("ORIGIN_MISMATCH", page)

    def test_rebinding_host_header_is_refused_for_reads(self):
        session = self.sign_in()
        status, _, page = self.request(
            "GET", "/", session=session, headers={"Host": "evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertIn("HOST_NOT_ALLOWED", page)

    def test_rebinding_host_header_is_refused_for_writes(self):
        session = self.sign_in()
        body = urlencode({"csrf": session["csrf"], "conversation_id": "0" * 32,
                          "question": "hi"})
        status, _, page = self.request(
            "POST", "/ask", body=body, session=session,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body)), "Host": "evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertIn("HOST_NOT_ALLOWED", page)

    def test_oversized_body_is_refused(self):
        session = self.sign_in()
        body = "x" * 20000
        status, _, page = self.request(
            "POST", "/ask", body=body, session=session,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body))},
        )
        self.assertEqual(status, 413)
        self.assertIn("BODY_TOO_LARGE", page)


class AskFlowTests(ServerTestCase):
    def test_successful_question_renders_the_model_reply(self):
        session = self.sign_in()
        status, headers, _ = self.ask(session, "Is dispatch halted?")
        self.assertEqual(status, 303)
        _, _, page = self.request("GET", "/", session=session)
        self.assertIn("Dispatch is not halted.", page)
        self.assertIn("SUCCEEDED", page)
        self.assertEqual(len(self.provider.calls), 1)

    def test_empty_question_is_refused(self):
        session = self.sign_in()
        status, _, page = self.ask(session, "")
        self.assertEqual(status, 400)
        self.assertIn("INVALID_QUESTION", page)

    def test_oversized_question_is_refused(self):
        session = self.sign_in()
        status, _, page = self.ask(session, "q" * 2500)
        self.assertEqual(status, 400)
        self.assertIn("INVALID_QUESTION", page)

    def test_conversation_must_belong_to_the_session_actor(self):
        session = self.sign_in()
        other = agent_state.create_conversation(self.ws.db_path, actor="other@example.test")
        status, _, page = self.ask(session, "hi", conversation_id=other)
        self.assertEqual(status, 403)
        self.assertIn("CONVERSATION_NOT_OWNED", page)

    def test_one_actor_cannot_read_anothers_turn(self):
        session = self.sign_in()
        self.ask(session, "Is dispatch halted?")
        _, _, page = self.request("GET", "/", session=session)
        import re

        turn_id = re.search(r"/turn/([0-9a-f]{32})", page).group(1)
        other = self.sign_in("other@example.test")
        status, _, _ = self.request("GET", f"/turn/{turn_id}", session=other)
        self.assertEqual(status, 404)

    def test_hostile_question_is_escaped_in_the_page(self):
        self.provider = ScriptedProvider(decision("<script>alert(1)</script>"))
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.config.provider = self.provider
        self.server = make_server(self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self._wait_ready()
        session = self.sign_in()
        hostile = '<img src=x onerror="alert(1)"><script>steal()</script>'
        self.ask(session, hostile)
        _, _, page = self.request("GET", "/", session=session)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("&lt;img src=x", page)

    def test_turn_receipt_page_shows_governance_evidence(self):
        session = self.sign_in()
        self.ask(session, "Is dispatch halted?")
        _, _, page = self.request("GET", "/", session=session)
        import re

        turn_id = re.search(r"/turn/([0-9a-f]{32})", page).group(1)
        status, _, detail = self.request("GET", f"/turn/{turn_id}", session=session)
        self.assertEqual(status, 200)
        self.assertIn("model.call", detail)
        self.assertIn(turn_id, detail)

    def test_reply_never_contains_a_provider_secret(self):
        session = self.sign_in()
        self.ask(session, "hello")
        _, _, page = self.request("GET", "/", session=session)
        for needle in ("Bearer", "sk-", "api_key", "CF_WORKERS_AI_TOKEN"):
            self.assertNotIn(needle, page)


class BudgetWebTests(ServerTestCase):
    def test_budget_exhaustion_returns_429(self):
        from shards_agent_os import web_server

        original = web_server.BUDGET_LIMIT
        web_server.BUDGET_LIMIT = 1
        try:
            session = self.sign_in()
            self.assertEqual(self.ask(session, "one")[0], 303)
            status, _, page = self.ask(session, "two")
            self.assertEqual(status, 429)
            self.assertIn("Request budget exhausted", page)
        finally:
            web_server.BUDGET_LIMIT = original


class BindRefusalTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()

    def tearDown(self):
        self.ws.close()

    def _config(self, **overrides):
        base = dict(
            db_path=self.ws.db_path, audience=AUDIENCE,
            provider=ScriptedProvider(decision("ok")),
            authority=self.ws.authority(), kernel_port=8765,
            edge_secret=EDGE_SECRET, host="127.0.0.1", port=free_port(),
        )
        base.update(overrides)
        return WebConfig(**base)

    def test_non_loopback_bind_is_refused(self):
        with self.assertRaises(WebError) as caught:
            make_server(self._config(host="0.0.0.0"))
        self.assertEqual(caught.exception.code, "NON_LOOPBACK_BIND_REFUSED")

    def test_weak_edge_secret_is_refused(self):
        with self.assertRaises(WebError) as caught:
            make_server(self._config(edge_secret=b"short"))
        self.assertEqual(caught.exception.code, "WEAK_EDGE_SECRET")

    def test_fixture_provider_is_refused_without_the_flag(self):
        from shards_agent_os.qwen_provider import FixtureProvider

        with self.assertRaises(WebError) as caught:
            make_server(self._config(provider=FixtureProvider('{"reply":"x","tool":null}')))
        self.assertEqual(caught.exception.code, "FIXTURE_PROVIDER_REFUSED")

    def test_fixture_provider_allowed_only_when_flagged(self):
        from shards_agent_os.qwen_provider import FixtureProvider

        server = make_server(self._config(
            provider=FixtureProvider('{"reply":"x","tool":null}'), allow_fixture=True,
        ))
        server.server_close()


if __name__ == "__main__":
    unittest.main()
