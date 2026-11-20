/**
 * Shards Agent OS — Cloudflare Worker edge integration.
 *
 * This module is a *patch to the existing* `shards-agent-hub-ai` Worker. It
 * does not replace the deployed Worker and it does not create a second chat
 * surface. It adds three things in front of the Agent OS origin:
 *
 *   1. Real Cloudflare Access JWT verification (RS256 against the team's
 *      published certs), so the origin receives a trustworthy actor identity
 *      instead of a spoofable header.
 *   2. A short-lived HMAC assertion that the origin verifies itself
 *      (`shards_agent_os.web_server.verify_assertion`). The origin never parses
 *      an Access JWT and holds no Cloudflare credential.
 *   3. Transparent proxying of the origin's server-rendered, no-JavaScript UI
 *      and its governed `/ask` route, plus the existing `/api/chat` path now
 *      calling the real Workers AI Qwen binding.
 *
 * Deliberate properties:
 *   - The Worker holds no model API key: `env.AI` is a credential-free binding.
 *   - No secret ever reaches the browser. The only cookie is the origin's own
 *     opaque session cookie, which the Worker forwards untouched.
 *   - The Worker cannot mint a tool permit or an observation delegation. Those
 *     are Ed25519 documents produced offline by an independent authority and
 *     verified only inside the origin process.
 *
 * Deployment status: NOT deployed from this repository. See
 * `deploy/cloudflare/README.md` for the exact operator steps and blockers.
 */

const ACCESS_CERTS_TTL_MS = 60 * 60 * 1000;
const MAX_CHAT_MESSAGES = 12;
const MAX_MESSAGE_CHARS = 2000;
const MAX_BODY_BYTES = 8192;
const QWEN_MODEL = "@cf/qwen/qwen3.8-27b";

/* ------------------------------------------------------------------ */
/* Access JWT verification                                            */
/* ------------------------------------------------------------------ */

const certCache = new Map();

function base64UrlToBytes(value) {
  const normalised = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalised + "=".repeat((4 - (normalised.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function decodeJsonSegment(segment) {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment)));
}

/**
 * Fetch and cache the Access team's signing keys.
 *
 * @param {string} teamDomain e.g. `gentle-shape-bee5.cloudflareaccess.com`
 * @param {typeof fetch} fetchImpl
 */
export async function loadAccessCerts(teamDomain, fetchImpl = fetch, nowMs = Date.now()) {
  if (!/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(teamDomain)) {
    throw new Error("INVALID_TEAM_DOMAIN");
  }
  const cached = certCache.get(teamDomain);
  if (cached && cached.expiresAt > nowMs) {
    return cached.keys;
  }
  const response = await fetchImpl(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!response.ok) {
    throw new Error("ACCESS_CERTS_UNAVAILABLE");
  }
  const body = await response.json();
  if (!Array.isArray(body.keys) || body.keys.length === 0) {
    throw new Error("ACCESS_CERTS_EMPTY");
  }
  certCache.set(teamDomain, { keys: body.keys, expiresAt: nowMs + ACCESS_CERTS_TTL_MS });
  return body.keys;
}

/** Test-only hook so the cache does not leak between cases. */
export function _clearCertCache() {
  certCache.clear();
}

async function importRsaKey(jwk) {
  if (jwk.kty !== "RSA" || jwk.alg !== "RS256" || !jwk.n || !jwk.e) {
    throw new Error("UNSUPPORTED_ACCESS_KEY");
  }
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

/**
 * Verify a Cloudflare Access JWT and return its claims.
 *
 * Rejects on: malformed token, unknown `kid`, bad signature, wrong `aud`,
 * wrong issuer, expired or not-yet-valid token.
 */
export async function verifyAccessJwt(token, options) {
  const { teamDomain, audience, fetchImpl = fetch, nowMs = Date.now() } = options;
  if (typeof token !== "string" || token.length < 32 || token.length > 8192) {
    throw new Error("INVALID_JWT");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("INVALID_JWT");
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts;
  let header;
  let payload;
  try {
    header = decodeJsonSegment(headerSegment);
    payload = decodeJsonSegment(payloadSegment);
  } catch {
    throw new Error("INVALID_JWT");
  }
  if (header.alg !== "RS256" || typeof header.kid !== "string") {
    throw new Error("UNSUPPORTED_JWT_ALGORITHM");
  }
  const keys = await loadAccessCerts(teamDomain, fetchImpl, nowMs);
  const jwk = keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk) {
    throw new Error("UNKNOWN_SIGNING_KEY");
  }
  const key = await importRsaKey(jwk);
  const signed = new TextEncoder().encode(`${headerSegment}.${payloadSegment}`);
  const valid = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    base64UrlToBytes(signatureSegment),
    signed,
  );
  if (!valid) {
    throw new Error("JWT_SIGNATURE_INVALID");
  }
  const nowSeconds = Math.floor(nowMs / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds) {
    throw new Error("JWT_EXPIRED");
  }
  if (typeof payload.nbf === "number" && payload.nbf > nowSeconds + 60) {
    throw new Error("JWT_NOT_YET_VALID");
  }
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(audience)) {
    throw new Error("JWT_AUDIENCE_MISMATCH");
  }
  if (typeof payload.iss !== "string" || !payload.iss.endsWith(".cloudflareaccess.com")) {
    throw new Error("JWT_ISSUER_INVALID");
  }
  const email = payload.email;
  if (typeof email !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,253}$/.test(email)) {
    throw new Error("JWT_SUBJECT_MISSING");
  }
  return { email, claims: payload };
}

/* ------------------------------------------------------------------ */
/* Origin assertion (must match the Python verifier byte for byte)    */
/* ------------------------------------------------------------------ */

function bytesToHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Mint the assertion the Agent OS origin verifies.
 *
 * Message format is fixed by `web_server.sign_assertion`:
 *   `${actor}\n${nonce}\n${tsMs}` signed with HMAC-SHA256, lowercase hex.
 */
export async function mintOriginAssertion(secret, { actor, nonce, tsMs }) {
  if (typeof secret !== "string" || secret.length < 32) {
    throw new Error("WEAK_ORIGIN_SECRET");
  }
  if (typeof actor !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,253}$/.test(actor)) {
    throw new Error("INVALID_ACTOR");
  }
  if (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
    throw new Error("INVALID_NONCE");
  }
  if (!Number.isInteger(tsMs) || tsMs <= 0) {
    throw new Error("INVALID_TIMESTAMP");
  }
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`${actor}\n${nonce}\n${tsMs}`),
  );
  return bytesToHex(signature);
}

function newNonce() {
  return crypto.randomUUID().replace(/-/g, "");
}

/* ------------------------------------------------------------------ */
/* Response helpers                                                   */
/* ------------------------------------------------------------------ */

const BASE_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
};

function json(status, payload, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...BASE_HEADERS,
      ...extraHeaders,
    },
  });
}

function errorPage(status, code) {
  const safe = String(code).replace(/[^A-Z0-9_]/g, "");
  return new Response(
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      "<title>Shards Agent OS</title>" +
      "<style>body{font:16px/1.55 system-ui,sans-serif;margin:0;padding:2rem 1rem;" +
      "background:#fbfbfd;color:#14161a}main{max-width:32rem;margin:0 auto}" +
      "code{font-family:ui-monospace,monospace}</style></head>" +
      '<body><main><h1 style="font-size:1.1rem">Shards Agent OS</h1>' +
      `<p>This request was refused.</p><p><code>${safe}</code></p></main></body></html>`,
    {
      status,
      headers: { "Content-Type": "text/html; charset=utf-8", ...BASE_HEADERS },
    },
  );
}

/* ------------------------------------------------------------------ */
/* Routes                                                             */
/* ------------------------------------------------------------------ */

async function readActor(request, env, nowMs) {
  const token =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    request.headers.get("cf-access-token");
  if (!token) {
    throw new Error("NO_ACCESS_JWT");
  }
  const { email } = await verifyAccessJwt(token, {
    teamDomain: env.ACCESS_TEAM_DOMAIN,
    audience: env.ACCESS_AUD,
    nowMs,
  });
  return email;
}

/**
 * Proxy a request to the Agent OS origin with a fresh signed assertion.
 *
 * The origin re-verifies the assertion, enforces its own session, CSRF, origin
 * and per-actor budget, and performs model inference plus governed dispatch.
 */
export async function proxyToOrigin(
  request,
  env,
  actor,
  fetchImpl = fetch,
  nowMs = Date.now(),
) {
  if (
    typeof env.ORIGIN_BASE_URL !== "string" ||
    !env.ORIGIN_BASE_URL.startsWith("https://")
  ) {
    throw new Error("ORIGIN_NOT_CONFIGURED");
  }
  const nonce = newNonce();
  const tsMs = nowMs;
  const signature = await mintOriginAssertion(env.ORIGIN_ASSERTION_SECRET, {
    actor,
    nonce,
    tsMs,
  });
  const target = new URL(request.url);
  const origin = new URL(env.ORIGIN_BASE_URL);
  // A pathname beginning with "//" is a protocol-relative URL when passed
  // to new URL(path, base): that would leak actor assertions to another host.
  // Assign URL components without ever reparsing untrusted path as authority.
  const url = new URL(origin.href);
  url.pathname = target.pathname;
  url.search = target.search;
  url.hash = "";

  // Never forward the browser's Access JWT: the origin does not understand it
  // and it is a bearer credential for a different audience.
  const headers = new Headers();
  for (const name of ["content-type", "cookie", "accept", "origin", "referer"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  headers.set("X-Shards-Actor", actor);
  headers.set("X-Shards-Assertion", `${nonce}.${tsMs}.${signature}`);
  headers.set("X-Forwarded-Host", target.host);

  const init = { method: request.method, headers, redirect: "manual" };
  if (request.method !== "GET" && request.method !== "HEAD") {
    const body = await request.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) {
      throw new Error("BODY_TOO_LARGE");
    }
    init.body = body;
  }
  const upstream = await fetchImpl(url.toString(), init);
  const responseHeaders = new Headers();
  for (const [name, value] of upstream.headers) {
    const lower = name.toLowerCase();
    if (["set-cookie", "content-type", "location", "content-security-policy",
         "cache-control"].includes(lower) || lower.startsWith("x-")) {
      responseHeaders.append(name, value);
    }
  }
  for (const [name, value] of Object.entries(BASE_HEADERS)) {
    responseHeaders.set(name, value);
  }
  return new Response(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

/**
 * Real Qwen inference through the existing Workers AI binding.
 *
 * This is the same `env.AI` binding the deployed Worker already uses; no model
 * key is involved and nothing is mocked.
 */
export async function handleChat(request, env, actor, nowMs = Date.now()) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return json(400, { error: "INVALID_JSON" });
  }
  const messages = payload && payload.messages;
  if (
    !Array.isArray(messages) ||
    messages.length === 0 ||
    messages.length > MAX_CHAT_MESSAGES
  ) {
    return json(400, { error: "INVALID_MESSAGES" });
  }
  const checked = [];
  for (const message of messages) {
    if (!message || typeof message.content !== "string") {
      return json(400, { error: "INVALID_MESSAGES" });
    }
    const role = message.role === "assistant" ? "assistant" : "user";
    if (message.content.length === 0 || message.content.length > MAX_MESSAGE_CHARS) {
      return json(400, { error: "INVALID_MESSAGES" });
    }
    checked.push({ role, content: message.content });
  }
  if (!env.AI || typeof env.AI.run !== "function") {
    return json(503, { error: "AI_BINDING_MISSING" });
  }
  const started = nowMs;
  let result;
  try {
    result = await env.AI.run(QWEN_MODEL, {
      messages: checked,
      max_tokens: 400,
      temperature: 0.1,
    });
  } catch {
    return json(502, { error: "INFERENCE_FAILED" });
  }
  const text = typeof result === "string" ? result : result && result.response;
  if (typeof text !== "string" || text.trim().length === 0) {
    return json(502, { error: "EMPTY_INFERENCE" });
  }
  return json(200, {
    reply: text,
    provider: "workers-ai",
    model: QWEN_MODEL,
    actor,
    latency_ms: Date.now() - started,
  });
}

/**
 * Governed read-only tool call.
 *
 * The Worker does not decide authority. It forwards the request to the origin,
 * which verifies the independent authority's signed artefact and dispatches
 * through the existing Shards-Kernel queue. A `DENIED` answer from the origin
 * is a real governance decision, not a Worker error.
 */
export async function handleAgentAsk(
  request,
  env,
  actor,
  fetchImpl = fetch,
  nowMs = Date.now(),
) {
  return proxyToOrigin(request, env, actor, fetchImpl, nowMs);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const nowMs = Date.now();
    try {
      if (url.pathname === "/api/health" && request.method === "GET") {
        // Health is deliberately unauthenticated but discloses no capability.
        return json(200, { status: "ok", service: "shards-agent-hub-ai" });
      }
      const actor = await readActor(request, env, nowMs);

      if (url.pathname === "/api/chat" && request.method === "POST") {
        return await handleChat(request, env, actor, nowMs);
      }
      if (url.pathname === "/api/models" && request.method === "GET") {
        return json(200, { models: [{ id: QWEN_MODEL, provider: "workers-ai" }] });
      }
      if (url.pathname === "/api/agents/ask") {
        return await handleAgentAsk(request, env, actor);
      }
      // The chat UI, receipts and governed /ask route are the origin's own
      // server-rendered pages. Proxy them rather than duplicating the surface.
      return await proxyToOrigin(request, env, actor, fetch, nowMs);
    } catch (error) {
      const code = error && error.message ? error.message : "EDGE_ERROR";
      const status =
        code === "NO_ACCESS_JWT" ? 401 : code === "BODY_TOO_LARGE" ? 413 : 403;
      if (url.pathname.startsWith("/api/")) {
        return json(status, { error: code });
      }
      return errorPage(status, code);
    }
  },
};
