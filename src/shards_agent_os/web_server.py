"""Mobile-first, server-rendered web surface for the governed Qwen agent.

Design constraints, all deliberate:

* **No JavaScript.** The page contains no ``<script>`` at all and the CSP
  forbids scripts, so a compromised model reply cannot execute in the owner's
  browser. The single control is a plain form POST.
* **No browser-held secrets.** The only cookie is an opaque random session id
  (``HttpOnly``, ``SameSite=Strict``); the model key, the authority key and the
  kernel permit never reach the browser.
* **Edge identity, origin session.** The trusted edge (Cloudflare Access via
  the Worker) hands the browser a short-lived HMAC-signed assertion. The origin
  verifies it, then issues its own session. The origin never parses a
  third-party token format and holds no Cloudflare API credential.
* **Loopback bind plus Host allowlist.** Reads and writes are both gated, so a
  DNS-rebinding page cannot drive the API.
* **Per-actor budget, bounded input, bounded timeout.** One question per
  request, capped length, capped provider timeout, capped model calls per turn.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from . import agent_state, agent_tools
from .agent_loop import LoopError, ToolAuthority, run_turn
from .qwen_provider import ModelProvider

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'; "
    "require-trusted-types-for 'script'"
)
MAX_BODY_BYTES = 8192
SESSION_COOKIE = "shards_agent_session"
SESSION_TTL_MS = 8 * 3600 * 1000
ASSERTION_MAX_SKEW_MS = 120_000
BUDGET_LIMIT = 20
BUDGET_WINDOW_MS = 3600 * 1000
_SAFE_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,253}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_MAX_QUESTION = 2000


class WebError(ValueError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass
class WebConfig:
    db_path: str
    audience: str
    provider: ModelProvider
    authority: ToolAuthority
    kernel_port: int
    edge_secret: bytes
    host: str = "127.0.0.1"
    port: int = 12000
    allow_fixture: bool = False
    edge_public_origin: str | None = None  # HTTPS public origin, explicitly configured
    sessions: dict[str, dict] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


def _connect(db_path: str):
    conn = agent_state._connect(db_path)  # noqa: SLF001 - same package
    conn.execute("""CREATE TABLE IF NOT EXISTS agent_sessions (
        session_id TEXT PRIMARY KEY, actor TEXT NOT NULL,
        csrf_token TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS agent_assertion_nonces (
        nonce TEXT PRIMARY KEY, seen_at_ms INTEGER NOT NULL)""")
    conn.commit()
    return conn


def ensure_web_schema(db_path: str) -> None:
    with _connect(db_path) as conn:
        conn.commit()


def _now_ms() -> int:
    return int(time.time() * 1000)


def sign_assertion(secret: bytes, *, actor: str, nonce: str, ts_ms: int) -> str:
    """HMAC over actor, nonce and timestamp. Used by the trusted edge and tests."""
    message = f"{actor}\n{nonce}\n{ts_ms}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_assertion(secret: bytes, *, actor: str, nonce: str, ts_ms: int,
                     signature: str, now_ms: int | None = None) -> None:
    if type(actor) is not str or not _SAFE_ACTOR.fullmatch(actor):
        raise WebError("INVALID_ACTOR", 403)
    if type(nonce) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        raise WebError("INVALID_NONCE", 403)
    if type(ts_ms) is not int or type(signature) is not str:
        raise WebError("INVALID_ASSERTION", 403)
    now = _now_ms() if now_ms is None else now_ms
    if abs(now - ts_ms) > ASSERTION_MAX_SKEW_MS:
        raise WebError("ASSERTION_EXPIRED", 403)
    expected = sign_assertion(secret, actor=actor, nonce=nonce, ts_ms=ts_ms)
    if not hmac.compare_digest(expected, signature):
        raise WebError("ASSERTION_INVALID", 403)


def _record_nonce(conn, nonce: str, now: int) -> None:
    """Consume an assertion exactly once; SQLite's unique key closes races."""
    try:
        conn.execute(
            "INSERT INTO agent_assertion_nonces (nonce, seen_at_ms) VALUES (?,?)",
            (nonce, now),
        )
    except sqlite3.IntegrityError:
        raise WebError("ASSERTION_REPLAYED", 403) from None
    conn.execute(
        "DELETE FROM agent_assertion_nonces WHERE seen_at_ms < ?",
        (now - 2 * ASSERTION_MAX_SKEW_MS,),
    )


def _consume_nonce(config: WebConfig, nonce: str) -> None:
    with _connect(config.db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        _record_nonce(conn, nonce, _now_ms())


def _create_session(config: WebConfig, *, actor: str,
                    assertion_nonce: str | None = None) -> tuple[str, str]:
    session_id, csrf = secrets.token_hex(16), secrets.token_urlsafe(32)
    now = _now_ms()
    with _connect(config.db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if assertion_nonce is not None:
            _record_nonce(conn, assertion_nonce, now)
        conn.execute(
            "INSERT INTO agent_sessions VALUES (?,?,?,?,?)",
            (session_id, actor, csrf, now, now + SESSION_TTL_MS),
        )
        conn.execute("DELETE FROM agent_sessions WHERE expires_at_ms <= ?", (now,))
    return session_id, csrf


def _load_session(config: WebConfig, session_id: str | None) -> dict | None:
    if not session_id or not _HEX32.fullmatch(session_id):
        return None
    with _connect(config.db_path) as conn:
        row = conn.execute(
            "SELECT session_id,actor,csrf_token,expires_at_ms FROM agent_sessions "
            "WHERE session_id=?", (session_id,),
        ).fetchone()
    if row is None or row["expires_at_ms"] <= _now_ms():
        return None
    return dict(row)


def _drop_session(config: WebConfig, session_id: str) -> None:
    if session_id and _HEX32.fullmatch(session_id):
        with _connect(config.db_path) as conn:
            conn.execute("DELETE FROM agent_sessions WHERE session_id=?", (session_id,))


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


_CSS = """
:root{color-scheme:light dark;--bg:#fbfbfd;--fg:#14161a;--muted:#5b6472;
--card:#ffffff;--line:#e3e6eb;--accent:#2f5bd7;--ok:#1c7a4a;--warn:#9a6200;
--bad:#a42222;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e8eaee;--muted:#98a1b0;
--card:#171a20;--line:#262b34;--accent:#7aa2ff;--ok:#4cc38a;--warn:#e0b34d;--bad:#ff8080}}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
padding:max(12px,env(safe-area-inset-top)) 12px calc(24px + env(safe-area-inset-bottom))}
.wrap{max-width:44rem;margin:0 auto}
header{display:flex;flex-wrap:wrap;gap:.5rem;align-items:baseline;
justify-content:space-between;margin-bottom:1rem}
h1{font-size:1.15rem;margin:0;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:.82rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;
padding:14px;margin-bottom:12px}
.turn{border-left:3px solid var(--line)}
.turn.ok{border-left-color:var(--ok)}
.turn.denied{border-left-color:var(--warn)}
.turn.failed,.turn.unknown{border-left-color:var(--bad)}
.q{font-weight:600;margin:0 0 .4rem}
.a{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.meta{display:flex;flex-wrap:wrap;gap:.35rem .9rem;color:var(--muted);
font-size:.76rem;margin-top:.6rem}
.pill{display:inline-block;padding:.08rem .5rem;border-radius:999px;
border:1px solid var(--line);font-size:.72rem;font-weight:600}
.pill.SUCCEEDED{color:var(--ok);border-color:currentColor}
.pill.DENIED{color:var(--warn);border-color:currentColor}
.pill.FAILED,.pill.UNKNOWN{color:var(--bad);border-color:currentColor}
label{display:block;font-size:.82rem;color:var(--muted);margin-bottom:.35rem}
textarea{width:100%;min-height:5.5rem;padding:.7rem;border-radius:10px;
border:1px solid var(--line);background:var(--bg);color:var(--fg);
font:inherit;resize:vertical}
button{margin-top:.6rem;width:100%;padding:.8rem 1rem;border:0;border-radius:10px;
background:var(--accent);color:#fff;font:inherit;font-weight:600}
button:disabled{opacity:.6}
form.inline{display:inline}
form.inline button{width:auto;margin:0;padding:.4rem .8rem;font-size:.8rem;
background:transparent;color:var(--accent);border:1px solid var(--line)}
a{color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th,td{text-align:left;padding:.4rem .3rem;border-bottom:1px solid var(--line);
vertical-align:top;overflow-wrap:anywhere}
th{color:var(--muted);font-weight:600}
code,.mono{font-family:var(--mono);font-size:.8rem}
.notice{border:1px solid var(--warn);color:var(--warn)}
.empty{color:var(--muted);font-size:.9rem}
"""


def _page(title: str, body: str, *, actor: str | None = None,
          csrf: str | None = None) -> str:
    logout = ""
    if actor and csrf:
        logout = (
            '<form class="inline" method="post" action="/logout">'
            f'<input type="hidden" name="csrf" value="{_escape(csrf)}">'
            '<button type="submit">Sign out</button></form>'
        )
    who = f'<div class="sub">signed in as {_escape(actor)}</div>' if actor else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>{_escape(title)} · Shards Agent OS</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<header><div><h1>Shards Agent OS</h1>{who}</div>{logout}</header>
{body}
<footer class="sub" style="margin-top:1.5rem">
Governed read-only tools. Replies come from a configured Qwen model; tool calls
require an independently signed grant. This page runs no JavaScript.
</footer>
</div></body></html>"""


def _turn_card(turn: dict) -> str:
    status = _escape(turn["status"])
    css = {"SUCCEEDED": "ok", "DENIED": "denied", "FAILED": "failed",
           "UNKNOWN": "unknown"}.get(turn["status"], "")
    parts = [
        f'<article class="card turn {css}">',
        f'<p class="q">{_escape(turn["question"])}</p>',
    ]
    if turn.get("reply"):
        parts.append(f'<p class="a">{_escape(turn["reply"])}</p>')
    meta = [f'<span class="pill {status}">{status}</span>']
    if turn.get("provider"):
        meta.append(f'<span>model {_escape(turn["provider"])} · {_escape(turn["model"] or "")}</span>')
    if turn.get("model_latency_ms") is not None:
        meta.append(f'<span>{int(turn["model_latency_ms"])} ms inference</span>')
    if turn.get("tool_name"):
        meta.append(f'<span>tool <code>{_escape(turn["tool_name"])}</code> '
                    f'({_escape(turn["tool_status"] or "")})</span>')
    if turn.get("error_code"):
        meta.append(f'<span>code <code>{_escape(turn["error_code"])}</code></span>')
    meta.append(f'<a href="/turn/{_escape(turn["turn_id"])}">receipts</a>')
    parts.append('<div class="meta">' + "".join(meta) + "</div>")
    parts.append("</article>")
    return "".join(parts)


def render_home(config: WebConfig, *, actor: str, csrf: str,
                conversation_id: str, notice: str | None = None) -> str:
    turns = agent_state.list_turns(
        config.db_path, actor=actor, conversation_id=conversation_id, limit=50,
    )
    notice_html = f'<div class="card notice">{_escape(notice)}</div>' if notice else ""
    history = "".join(_turn_card(turn) for turn in turns) or (
        '<p class="empty">No questions yet. Ask about local dispatch state, or try '
        'the reference <code>kernel.echo</code> / <code>kernel.add</code> tools.</p>'
    )
    body = f"""{notice_html}
<div class="card">
<form method="post" action="/ask">
<input type="hidden" name="csrf" value="{_escape(csrf)}">
<input type="hidden" name="conversation_id" value="{_escape(conversation_id)}">
<label for="q">Your question</label>
<textarea id="q" name="question" maxlength="{_MAX_QUESTION}" required
placeholder="Is dispatch halted? How many jobs are queued?"></textarea>
<button type="submit">Ask Qwen</button>
</form>
</div>
{history}"""
    return _page("Chat", body, actor=actor, csrf=csrf)


def render_turn(config: WebConfig, *, actor: str, turn: dict) -> str:
    rows = []
    for receipt in turn["receipts"]:
        payload = json.dumps(receipt["payload"], indent=2, sort_keys=True)
        rows.append(
            f'<tr><td class="mono">{_escape(receipt["kind"])}</td>'
            f'<td><pre class="mono" style="margin:0;white-space:pre-wrap">'
            f'{_escape(payload)}</pre></td></tr>'
        )
    table = ("<table><thead><tr><th>kind</th><th>payload</th></tr></thead><tbody>"
             + "".join(rows) + "</tbody></table>") if rows else (
        '<p class="empty">No receipts recorded for this turn.</p>')
    body = f"""<div class="card">
<p class="sub"><a href="/">← back to chat</a></p>
<p class="q">{_escape(turn["question"])}</p>
<p class="a">{_escape(turn.get("reply") or "(no reply)")}</p>
<div class="meta"><span class="pill {_escape(turn["status"])}">{_escape(turn["status"])}</span>
<span>turn <code>{_escape(turn["turn_id"])}</code></span>
{f'<span>job <code>{_escape(turn["job_id"])}</code></span>' if turn.get("job_id") else ""}
{f'<span>grant <code>{_escape(turn["grant_id"])}</code></span>' if turn.get("grant_id") else ""}
</div></div>
<div class="card"><h2 style="font-size:.95rem;margin:0 0 .6rem">Receipts</h2>{table}</div>"""
    return _page("Turn", body, actor=actor)


def _parse_form(body: bytes) -> dict[str, str]:
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        raise WebError("INVALID_ENCODING") from None
    parsed = parse_qs(text, keep_blank_values=True, strict_parsing=False,
                      max_num_fields=16)
    return {key: values[0] for key, values in parsed.items() if values}


class AgentRequestHandler(BaseHTTPRequestHandler):
    server_version = "ShardsAgentOS/0.4"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    config: WebConfig  # set by make_server

    # --- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102 - quiet
        return

    def _edge_claim(self) -> tuple[str, str] | None:
        """Verify the edge assertion independently of browser cookies.

        Only a valid signed edge assertion can enable the public Host/Origin
        path. The public origin must be explicitly configured by the operator.
        """
        if hasattr(self, "_cached_edge_claim"):
            return self._cached_edge_claim
        actor = self.headers.get("X-Shards-Actor")
        packed = self.headers.get("X-Shards-Assertion")
        forwarded_host = self.headers.get("X-Forwarded-Host")
        if actor is None and packed is None and forwarded_host is None:
            self._cached_edge_claim = None
            return None
        if not actor or not packed or not forwarded_host:
            raise WebError("EDGE_ASSERTION_MISSING", 403)
        public_origin = self.config.edge_public_origin
        if not public_origin:
            raise WebError("EDGE_NOT_CONFIGURED", 403)
        parsed = urlsplit(public_origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.path or parsed.query or parsed.fragment
                or forwarded_host.lower() != parsed.netloc.lower()):
            raise WebError("EDGE_HOST_INVALID", 403)
        parts = packed.split(".")
        if len(parts) != 3:
            raise WebError("INVALID_ASSERTION", 403)
        nonce, timestamp, signature = parts
        if not timestamp.isascii() or not timestamp.isdecimal():
            raise WebError("INVALID_ASSERTION", 403)
        verify_assertion(self.config.edge_secret, actor=actor, nonce=nonce,
                         ts_ms=int(timestamp), signature=signature)
        self._cached_edge_claim = (actor, nonce)
        return self._cached_edge_claim

    def _allowed_host(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        expected = {f"{self.config.host}:{self.config.port}",
                    f"localhost:{self.config.port}",
                    f"127.0.0.1:{self.config.port}"}
        edge = self._edge_claim()
        return bool(edge) or host in expected

    def _send(self, status: int, body: str, *, content_type: str = "text/html; charset=utf-8",
              headers: dict[str, str] | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        pending_cookie = getattr(self, "_pending_edge_cookie", None)
        if pending_cookie and "Set-Cookie" not in (headers or {}):
            self.send_header("Set-Cookie", pending_cookie)
        if status >= 400:
            # An error may leave an unread body on the socket. Closing avoids
            # parsing leftover bytes as a new request.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _session(self) -> dict | None:
        raw = self.headers.get("Cookie") or ""
        session = None
        for chunk in raw.split(";"):
            name, _, value = chunk.strip().partition("=")
            if name == SESSION_COOKIE:
                session = _load_session(self.config, value)
                break
        edge = self._edge_claim()
        if edge is None:
            return session
        actor, nonce = edge
        if session is not None and session["actor"] != actor:
            raise WebError("EDGE_ACTOR_MISMATCH", 403)
        if session is not None:
            _consume_nonce(self.config, nonce)
            return session
        if self.command != "GET":
            raise WebError("NOT_SIGNED_IN", 401)
        session_id, csrf = _create_session(
            self.config, actor=actor, assertion_nonce=nonce,
        )
        self._pending_edge_cookie = (
            f"{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; Secure; "
            f"SameSite=Strict; Max-Age={SESSION_TTL_MS // 1000}"
        )
        return {"session_id": session_id, "actor": actor, "csrf_token": csrf,
                "expires_at_ms": _now_ms() + SESSION_TTL_MS}

    def _require_session(self) -> dict:
        session = self._session()
        if session is None:
            raise WebError("NOT_SIGNED_IN", 401)
        return session

    def _check_origin(self) -> None:
        origin = self.headers.get("Origin")
        referer = self.headers.get("Referer")
        expected = {f"http://{self.config.host}:{self.config.port}"}
        if self._edge_claim():
            expected.add(self.config.edge_public_origin)
        for value in (origin, referer):
            if not value:
                continue
            parts = urlsplit(value)
            if f"{parts.scheme}://{parts.netloc}" not in expected:
                raise WebError("ORIGIN_MISMATCH", 403)

    def _check_csrf(self, form: dict[str, str], session: dict) -> None:
        token = form.get("csrf", "")
        if not hmac.compare_digest(token, session["csrf_token"]):
            raise WebError("CSRF_INVALID", 403)

    def _read_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        if length is None:
            raise WebError("LENGTH_REQUIRED", 411)
        try:
            size = int(length)
        except ValueError:
            raise WebError("INVALID_LENGTH") from None
        if size < 0 or size > MAX_BODY_BYTES:
            raise WebError("BODY_TOO_LARGE", 413)
        if size == 0:
            raise WebError("EMPTY_BODY")
        return self.rfile.read(size)

    # --- routes -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        try:
            if not self._allowed_host():
                raise WebError("HOST_NOT_ALLOWED", 403)
            path = urlsplit(self.path).path
            if path == "/api/health":
                return self._send(200, json.dumps({
                    "status": "ok", "service": "shards-agent-os",
                    "provider": self.config.provider.name,
                    "model": getattr(self.config.provider, "model", None),
                    "javascript": False,
                }), content_type="application/json")
            if path == "/auth/callback":
                return self._auth_callback()
            session = self._require_session()
            if path == "/":
                conversation_id = self._ensure_conversation(session["actor"])
                return self._send(200, render_home(
                    self.config, actor=session["actor"], csrf=session["csrf_token"],
                    conversation_id=conversation_id,
                ))
            if path.startswith("/turn/"):
                turn_id = path[len("/turn/"):]
                turn = agent_state.get_turn(
                    self.config.db_path, turn_id=turn_id, actor=session["actor"],
                )
                return self._send(200, render_turn(
                    self.config, actor=session["actor"], turn=turn,
                ))
            raise WebError("NOT_FOUND", 404)
        except WebError as exc:
            return self._send(exc.status, _page("Error",
                f'<div class="card notice">{_escape(exc.code)}</div>'))
        except ValueError:
            return self._send(404, _page("Error",
                '<div class="card notice">NOT_FOUND</div>'))

    def do_HEAD(self) -> None:  # noqa: N802 - http.server API
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        try:
            if not self._allowed_host():
                raise WebError("HOST_NOT_ALLOWED", 403)
            self._check_origin()
            path = urlsplit(self.path).path
            if path == "/auth/exchange":
                return self._auth_exchange()
            if path == "/logout":
                session = self._require_session()
                form = _parse_form(self._read_body())
                self._check_csrf(form, session)
                _drop_session(self.config, session["session_id"])
                return self._send(303, "", headers={
                    "Location": "/",
                    "Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0; "
                                  "HttpOnly; SameSite=Strict",
                })
            if path == "/ask":
                return self._ask()
            raise WebError("NOT_FOUND", 404)
        except WebError as exc:
            return self._send(exc.status, _page("Error",
                f'<div class="card notice">{_escape(exc.code)}</div>'))
        except ValueError:
            return self._send(400, _page("Error",
                '<div class="card notice">INVALID_REQUEST</div>'))

    # --- handlers ---------------------------------------------------------

    def _auth_callback(self) -> None:
        query = parse_qs(urlsplit(self.path).query, max_num_fields=8)
        actor = (query.get("actor") or [""])[0]
        nonce = (query.get("nonce") or [""])[0]
        signature = (query.get("sig") or [""])[0]
        try:
            ts_ms = int((query.get("ts") or ["0"])[0])
        except ValueError:
            raise WebError("INVALID_ASSERTION", 403) from None
        verify_assertion(self.config.edge_secret, actor=actor, nonce=nonce,
                         ts_ms=ts_ms, signature=signature)
        session_id, _csrf = _create_session(
            self.config, actor=actor, assertion_nonce=nonce,
        )
        self._send(303, "", headers={
            "Location": "/",
            "Set-Cookie": f"{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; "
                          f"SameSite=Strict; Max-Age={SESSION_TTL_MS // 1000}",
        })

    def _auth_exchange(self) -> None:
        """JSON variant for the Worker: verify an assertion, mint a session."""
        try:
            payload = json.loads(self._read_body().decode("utf-8"))
        except (UnicodeError, ValueError):
            raise WebError("INVALID_ASSERTION", 403) from None
        if type(payload) is not dict:
            raise WebError("INVALID_ASSERTION", 403)
        verify_assertion(
            self.config.edge_secret, actor=payload.get("actor"),
            nonce=payload.get("nonce"), ts_ms=payload.get("ts"),
            signature=payload.get("sig"),
        )
        session_id, csrf = _create_session(
            self.config, actor=payload["actor"], assertion_nonce=payload["nonce"],
        )
        self._send(200, json.dumps({"session": session_id, "csrf": csrf}),
                   content_type="application/json")

    def _ensure_conversation(self, actor: str) -> str:
        with _connect(self.config.db_path) as conn:
            row = conn.execute(
                "SELECT conversation_id FROM agent_conversations WHERE actor=? "
                "ORDER BY created_at_ms DESC LIMIT 1", (actor,),
            ).fetchone()
        if row:
            return row["conversation_id"]
        return agent_state.create_conversation(self.config.db_path, actor=actor)

    def _ask(self) -> None:
        session = self._require_session()
        form = _parse_form(self._read_body())
        self._check_csrf(form, session)
        actor = session["actor"]
        question = (form.get("question") or "").strip()
        conversation_id = form.get("conversation_id") or ""
        if not 1 <= len(question) <= _MAX_QUESTION:
            raise WebError("INVALID_QUESTION")
        if not agent_state.conversation_belongs_to(
            self.config.db_path, conversation_id=conversation_id, actor=actor
        ):
            raise WebError("CONVERSATION_NOT_OWNED", 403)
        if not agent_state.consume_budget(
            self.config.db_path, actor=actor, limit=BUDGET_LIMIT,
            window_ms=BUDGET_WINDOW_MS,
        ):
            return self._send(429, _page("Budget", (
                '<div class="card notice">Request budget exhausted for this hour.</div>'
                '<p class="sub"><a href="/">← back</a></p>'
            ), actor=actor, csrf=session["csrf_token"]))
        try:
            run_turn(
                self.config.db_path, actor=actor, conversation_id=conversation_id,
                question=question, provider=self.config.provider,
                authority=self.config.authority, kernel_port=self.config.kernel_port,
                allow_fixture=self.config.allow_fixture,
            )
        except LoopError as exc:
            return self._send(503, _page("Unavailable", (
                f'<div class="card notice">{_escape(exc.code)}</div>'
                '<p class="sub"><a href="/">← back</a></p>'
            ), actor=actor, csrf=session["csrf_token"]))
        self._send(303, "", headers={"Location": "/"})


def make_server(config: WebConfig) -> ThreadingHTTPServer:
    """Bind the loopback listener. Refuse any non-loopback host outright."""
    if config.host not in ("127.0.0.1", "::1", "localhost"):
        raise WebError("NON_LOOPBACK_BIND_REFUSED", 403)
    if config.provider.name == "fixture" and not config.allow_fixture:
        raise WebError("FIXTURE_PROVIDER_REFUSED", 403)
    if type(config.edge_secret) is not bytes or len(config.edge_secret) < 32:
        raise WebError("WEAK_EDGE_SECRET", 403)
    ensure_web_schema(config.db_path)
    handler = type("BoundAgentHandler", (AgentRequestHandler,), {"config": config})
    server = ThreadingHTTPServer((config.host, config.port), handler)
    server.daemon_threads = True
    return server


def _secret_from_env(name: str) -> bytes:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", name or ""):
        raise WebError("INVALID_SECRET_ENV_NAME", 403)
    value = os.environ.get(name)
    if not value or len(value) < 32:
        raise WebError("EDGE_SECRET_MISSING", 403)
    return value.encode("utf-8")
