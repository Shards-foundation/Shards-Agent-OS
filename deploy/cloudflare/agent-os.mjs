// Return null for routes owned by the hub. Never fall through inside the mount.
import { proxyToOrigin, readActor } from "./worker.mjs";

export async function routeAgentOS(request, env) {
  const path = new URL(request.url).pathname;
  if (path !== "/agent-os" && !path.startsWith("/agent-os/")) return null;
  try {
    const actor = await readActor(request, env, Date.now());
    if (path === "/agent-os" && request.method === "GET") {
      return new Response(null, { status: 308, headers: { Location: "/agent-os/", "Cache-Control": "no-store" } });
    }
    const page = path === "/agent-os/" || /^\/agent-os\/turn\/[a-f0-9]{32}$/.test(path);
    const form = path === "/agent-os/ask" || path === "/agent-os/logout";
    if (!page && !form) return new Response(null, { status: 404 });
    const allow = page ? "GET, HEAD" : "POST";
    if (page ? !["GET", "HEAD"].includes(request.method) : request.method !== "POST") {
      return new Response(null, { status: 405, headers: { Allow: allow } });
    }
    return await proxyToOrigin(request, env, actor);
  } catch (error) {
    const status = error.message === "NO_ACCESS_JWT" ? 401 :
      error.message === "BODY_TOO_LARGE" ? 413 : 403;
    return new Response(null, { status, headers: { "Cache-Control": "no-store" } });
  }
}

// Standalone entry for the isolated staging bundle.
export default {
  async fetch(request, env) {
    return await routeAgentOS(request, env) ?? new Response(null, { status: 404 });
  },
};
