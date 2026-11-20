/**
 * Worker tests. Run with: node --test deploy/cloudflare/
 *
 * These exercise real cryptographic paths: RS256 Access JWT verification
 * against a locally generated key pair, and HMAC assertions that the Python
 * origin verifies. No network call and no Cloudflare credential is used.
 */

import assert from "node:assert/strict";
import { test, before, beforeEach } from "node:test";
import { webcrypto } from "node:crypto";

import worker, {
  _clearCertCache,
  handleChat,
  mintOriginAssertion,
  proxyToOrigin,
  verifyAccessJwt,
} from "./worker.mjs";

const TEAM_DOMAIN = "example-team.cloudflareaccess.com";
const AUDIENCE = "a".repeat(64);
const ORIGIN_SECRET = "origin-secret-0123456789abcdefghijklmnop";
const ORIGIN_BASE = "https://origin.internal.example";

let signingKey;
let otherKey;
let jwk;
let otherJwk;

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function makeToken({ key = signingKey, kid = "key-1", payload = {}, alg = "RS256" } = {}) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const header = { alg, kid, typ: "JWT" };
  const claims = {
    aud: [AUDIENCE],
    email: "owner@example.test",
    iss: `https://${TEAM_DOMAIN}`,
    exp: nowSeconds + 600,
    iat: nowSeconds - 10,
    nbf: nowSeconds - 10,
    ...payload,
  };
  const head = b64url(Buffer.from(JSON.stringify(header)));
  const body = b64url(Buffer.from(JSON.stringify(claims)));
  const signature = await webcrypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key.privateKey,
    new TextEncoder().encode(`${head}.${body}`),
  );
  return `${head}.${body}.${b64url(new Uint8Array(signature))}`;
}

function certsFetcher(keys) {
  return async () => new Response(JSON.stringify({ keys }), { status: 200 });
}

function request(path, { method = "GET", headers = {}, body } = {}) {
  return new Request(`https://agents.shardsinc.co.uk${path}`, { method, headers, body });
}

const ENV = {
  ACCESS_TEAM_DOMAIN: TEAM_DOMAIN,
  ACCESS_AUD: AUDIENCE,
  ORIGIN_BASE_URL: ORIGIN_BASE,
  ORIGIN_ASSERTION_SECRET: ORIGIN_SECRET,
};

before(async () => {
  const rsa = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  signingKey = await webcrypto.subtle.generateKey(rsa, true, ["sign", "verify"]);
  otherKey = await webcrypto.subtle.generateKey(rsa, true, ["sign", "verify"]);
  const exportPublic = async (pair, kid) => {
    const exported = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
    return { kid, kty: "RSA", alg: "RS256", use: "sig", n: exported.n, e: exported.e };
  };
  jwk = await exportPublic(signingKey, "key-1");
  otherJwk = await exportPublic(otherKey, "key-2");
});

beforeEach(() => {
  _clearCertCache();
});

/* -------------------------- Access JWT ---------------------------- */

test("a valid Access JWT is accepted and yields the actor email", async () => {
  const token = await makeToken();
  const result = await verifyAccessJwt(token, {
    teamDomain: TEAM_DOMAIN,
    audience: AUDIENCE,
    fetchImpl: certsFetcher([jwk]),
  });
  assert.equal(result.email, "owner@example.test");
});

test("a token signed by an unknown key is rejected", async () => {
  const token = await makeToken({ key: otherKey, kid: "key-2" });
  await assert.rejects(
    verifyAccessJwt(token, {
      teamDomain: TEAM_DOMAIN,
      audience: AUDIENCE,
      fetchImpl: certsFetcher([jwk]),
    }),
    /UNKNOWN_SIGNING_KEY/,
  );
});

test("a token whose signature does not match its kid is rejected", async () => {
  const token = await makeToken({ key: otherKey, kid: "key-1" });
  await assert.rejects(
    verifyAccessJwt(token, {
      teamDomain: TEAM_DOMAIN,
      audience: AUDIENCE,
      fetchImpl: certsFetcher([jwk]),
    }),
    /JWT_SIGNATURE_INVALID/,
  );
});

test("a tampered payload invalidates the signature", async () => {
  const token = await makeToken();
  const [head, , sig] = token.split(".");
  const forged = b64url(
    Buffer.from(
      JSON.stringify({
        aud: [AUDIENCE],
        email: "attacker@example.test",
        iss: `https://${TEAM_DOMAIN}`,
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    ),
  );
  await assert.rejects(
    verifyAccessJwt(`${head}.${forged}.${sig}`, {
      teamDomain: TEAM_DOMAIN,
      audience: AUDIENCE,
      fetchImpl: certsFetcher([jwk]),
    }),
    /JWT_SIGNATURE_INVALID/,
  );
});

test("an expired token is rejected", async () => {
  const token = await makeToken({ payload: { exp: Math.floor(Date.now() / 1000) - 5 } });
  await assert.rejects(
    verifyAccessJwt(token, {
      teamDomain: TEAM_DOMAIN,
      audience: AUDIENCE,
      fetchImpl: certsFetcher([jwk]),
    }),
    /JWT_EXPIRED/,
  );
});

test("a token for another audience is rejected", async () => {
  const token = await makeToken({ payload: { aud: ["some-other-app"] } });
  await assert.rejects(
    verifyAccessJwt(token, {
      teamDomain: TEAM_DOMAIN,
      audience: AUDIENCE,
      fetchImpl: certsFetcher([jwk]),
    }),
    /JWT_AUDIENCE_MISMATCH/,
  );
});

test("a token with a foreign issuer is rejected", async () => {
  const token = await makeToken({ payload: { iss: "https://evil.example" } });
  await assert.rejects(
    verifyAccessJwt(token, {
      teamDomain: TEAM_DOMAIN,
      audience: AUDIENCE,
      fetchImpl: certsFetcher([jwk]),
    }),
    /JWT_ISSUER_INVALID/,
  );
});

test("alg=none is refused", async () => {
  const head = b64url(Buffer.from(JSON.stringify({ alg: "none", kid: "key-1" })));
  const body = b64url(Buffer.from(JSON.stringify({ email: "x@y.z", aud: [AUDIENCE] })));
  await assert.rejects(
    verifyAccessJwt(`${head}.${body}.sig`, {
      teamDomain: TEAM_DOMAIN,
      audience: AUDIENCE,
      fetchImpl: certsFetcher([jwk]),
    }),
    /UNSUPPORTED_JWT_ALGORITHM/,
  );
});

test("a malformed token is refused", async () => {
  for (const bad of ["", "abc", "a.b", "a.b.c.d", "x".repeat(9000)]) {
    await assert.rejects(
      verifyAccessJwt(bad, {
        teamDomain: TEAM_DOMAIN,
        audience: AUDIENCE,
        fetchImpl: certsFetcher([jwk]),
      }),
    );
  }
});

test("the cert endpoint must be the team's own domain", async () => {
  await assert.rejects(
    verifyAccessJwt(await makeToken(), {
      teamDomain: "evil.example",
      audience: AUDIENCE,
      fetchImpl: certsFetcher([jwk]),
    }),
    /INVALID_TEAM_DOMAIN/,
  );
});

/* ---------------------- Origin assertion --------------------------- */

test("the origin assertion matches the documented message format", async () => {
  const signature = await mintOriginAssertion(ORIGIN_SECRET, {
    actor: "owner@example.test",
    nonce: "nonce-0123456789abcdef",
    tsMs: 1795140000000,
  });
  assert.match(signature, /^[0-9a-f]{64}$/);
  // Independent recomputation with node:crypto, the same primitive Python uses.
  const { createHmac } = await import("node:crypto");
  const expected = createHmac("sha256", ORIGIN_SECRET)
    .update("owner@example.test\nnonce-0123456789abcdef\n1795140000000")
    .digest("hex");
  assert.equal(signature, expected);
});

test("a weak origin secret is refused", async () => {
  await assert.rejects(
    mintOriginAssertion("short", { actor: "a@b.c", nonce: "nonce-0123456789abcdef", tsMs: 1 }),
    /WEAK_ORIGIN_SECRET/,
  );
});

test("an unsafe actor or nonce is refused", async () => {
  await assert.rejects(
    mintOriginAssertion(ORIGIN_SECRET, { actor: "a b", nonce: "nonce-0123456789abcdef", tsMs: 1 }),
    /INVALID_ACTOR/,
  );
  await assert.rejects(
    mintOriginAssertion(ORIGIN_SECRET, { actor: "a@b.c", nonce: "short", tsMs: 1 }),
    /INVALID_NONCE/,
  );
});

/* --------------------------- Chat route ---------------------------- */

test("chat calls the real AI binding and returns its text", async () => {
  const calls = [];
  const env = {
    AI: {
      async run(model, payload) {
        calls.push({ model, payload });
        return { response: "Paris is the capital of France." };
      },
    },
  };
  const response = await handleChat(
    request("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "Capital of France?" }] }),
    }),
    env,
    "owner@example.test",
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.reply, "Paris is the capital of France.");
  assert.equal(body.provider, "workers-ai");
  assert.equal(body.model, "@cf/qwen/qwen3.8-27b");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].model, "@cf/qwen/qwen3.8-27b");
});

test("chat refuses an oversized message", async () => {
  const env = { AI: { async run() { return { response: "x" }; } } };
  const response = await handleChat(
    request("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "z".repeat(2001) }] }),
    }),
    env,
    "owner@example.test",
  );
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "INVALID_MESSAGES");
});

test("chat refuses too many messages", async () => {
  const env = { AI: { async run() { return { response: "x" }; } } };
  const messages = Array.from({ length: 13 }, () => ({ role: "user", content: "hi" }));
  const response = await handleChat(
    request("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages }),
    }),
    env,
    "owner@example.test",
  );
  assert.equal(response.status, 400);
});

test("chat reports a missing binding instead of inventing a reply", async () => {
  const response = await handleChat(
    request("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
    }),
    {},
    "owner@example.test",
  );
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, "AI_BINDING_MISSING");
});

test("chat never leaks an upstream exception message", async () => {
  const env = { AI: { async run() { throw new Error("token sk-live-abc leaked"); } } };
  const response = await handleChat(
    request("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
    }),
    env,
    "owner@example.test",
  );
  assert.equal(response.status, 502);
  const text = await response.text();
  assert.ok(!text.includes("sk-live"));
});

/* ------------------------ Proxy behaviour -------------------------- */

test("the proxy forwards an assertion and never the Access JWT", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return new Response("<html>origin</html>", {
      status: 200,
      headers: { "Content-Type": "text/html", "Set-Cookie": "shards_agent_session=abc; HttpOnly" },
    });
  };
  const response = await proxyToOrigin(
    request("/", {
      headers: {
        "Cf-Access-Jwt-Assertion": "browser-jwt-value",
        Cookie: "shards_agent_session=abc",
      },
    }),
    ENV,
    "owner@example.test",
    fetchImpl,
  );
  assert.equal(response.status, 200);
  assert.equal(captured.url, `${ORIGIN_BASE}/`);
  assert.equal(captured.init.headers.get("X-Shards-Actor"), "owner@example.test");
  assert.match(captured.init.headers.get("X-Shards-Assertion"), /^[0-9a-f]{32}\.\d+\.[0-9a-f]{64}$/);
  assert.equal(captured.init.headers.get("Cf-Access-Jwt-Assertion"), null);
  assert.equal(captured.init.headers.get("cookie"), "shards_agent_session=abc");
  assert.equal(response.headers.get("Set-Cookie"), "shards_agent_session=abc; HttpOnly");
});

test("the proxy preserves the HTML content type and same-origin redirect", async () => {
  const fetchImpl = async () => new Response("", {
    status: 303,
    headers: {
      "Location": "/",
      "Set-Cookie": "shards_agent_session=abc; HttpOnly; Secure; SameSite=Strict",
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'",
    },
  });
  const response = await proxyToOrigin(request("/auth/callback"), ENV,
    "owner@example.test", fetchImpl);
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Location"), "/");
  assert.match(response.headers.get("Content-Type"), /^text\/html/);
  assert.equal(response.headers.get("Content-Security-Policy"), "default-src 'none'");
  assert.match(response.headers.get("Set-Cookie"), /Secure/);
});

test("the proxy forwards browser Origin but never an untrusted actor", async () => {
  let captured;
  const fetchImpl = async (_url, init) => {
    captured = init.headers;
    return new Response("ok");
  };
  const response = await proxyToOrigin(
    request("/ask", {
      method: "POST",
      headers: {
        Origin: "https://agents.shardsinc.co.uk",
        Referer: "https://agents.shardsinc.co.uk/",
        "X-Shards-Actor": "attacker@example.test",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "question=test",
    }),
    ENV, "owner@example.test", fetchImpl,
  );
  assert.equal(response.status, 200);
  assert.equal(captured.get("origin"), "https://agents.shardsinc.co.uk");
  assert.equal(captured.get("referer"), "https://agents.shardsinc.co.uk/");
  assert.equal(captured.get("X-Shards-Actor"), "owner@example.test");
  assert.equal(captured.get("X-Forwarded-Host"), "agents.shardsinc.co.uk");
});

test("protocol-relative paths cannot redirect signed proxy requests to another host", async () => {
  for (const pathname of [
    "//attacker.example/steal?item=1",
    "/%2F%2Fattacker.example/steal",
  ]) {
    let destination;
    let forwarded;
    const fetchImpl = async (url, init) => {
      destination = new URL(url);
      forwarded = init.headers;
      return new Response("safe");
    };
    const response = await proxyToOrigin(
      request(pathname, {
        headers: { Cookie: "shards_agent_session=sensitive" },
      }),
      ENV, "owner@example.test", fetchImpl,
    );
    assert.equal(response.status, 200);
    assert.equal(destination.origin, ORIGIN_BASE);
    assert.equal(destination.hostname, "origin.internal.example");
    assert.equal(forwarded.get("cookie"), "shards_agent_session=sensitive");
    assert.match(forwarded.get("X-Shards-Assertion"), /^[0-9a-f]{32}\.\d+\.[0-9a-f]{64}$/);
  }
});

test("the proxy refuses a non-https origin", async () => {
  await assert.rejects(
    proxyToOrigin(request("/"), { ...ENV, ORIGIN_BASE_URL: "http://origin.example" },
      "owner@example.test", async () => new Response("x")),
    /ORIGIN_NOT_CONFIGURED/,
  );
});

test("the proxy refuses an oversized POST body", async () => {
  await assert.rejects(
    proxyToOrigin(
      request("/ask", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "x".repeat(9000),
      }),
      ENV,
      "owner@example.test",
      async () => new Response("x"),
    ),
    /BODY_TOO_LARGE/,
  );
});

/* --------------------------- Worker entry -------------------------- */

test("health is reachable without a token and discloses no capability", async () => {
  const response = await worker.fetch(request("/api/health"), ENV);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body, { status: "ok", service: "shards-agent-hub-ai" });
});

test("a page request without an Access JWT is refused with 401", async () => {
  const response = await worker.fetch(request("/"), ENV);
  assert.equal(response.status, 401);
  const text = await response.text();
  assert.ok(text.includes("NO_ACCESS_JWT"));
});

test("an API request without an Access JWT returns JSON 401", async () => {
  const response = await worker.fetch(request("/api/chat", { method: "POST", body: "{}" }), ENV);
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error, "NO_ACCESS_JWT");
});

test("the refusal page escapes the error code", async () => {
  const response = await worker.fetch(request("/"), ENV);
  const text = await response.text();
  assert.ok(!text.includes("<script"));
  assert.ok(!text.includes("onerror"));
});

test("a spoofed X-Shards-Actor header cannot substitute for an Access JWT", async () => {
  // The only accepted identity source is a verified Access JWT; a caller-set
  // actor header must never be trusted.
  const response = await worker.fetch(
    request("/", { headers: { "X-Shards-Actor": "admin@example.test" } }),
    ENV,
  );
  assert.equal(response.status, 401);
  assert.equal((await response.json().catch(() => ({}))).error, undefined);
});

test("a forged assertion header is not accepted by the edge", async () => {
  const response = await worker.fetch(
    request("/", {
      headers: { "X-Shards-Assertion": `${"a".repeat(32)}.1.${"b".repeat(64)}` },
    }),
    ENV,
  );
  assert.equal(response.status, 401);
});

test("an unauthenticated request never reaches the origin", async () => {
  let called = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    called = true;
    return new Response("should not happen");
  };
  try {
    const response = await worker.fetch(request("/ask", { method: "POST", body: "x" }), ENV);
    assert.equal(response.status, 401);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
