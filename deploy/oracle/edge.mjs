import { routeAgentOS } from "../cloudflare/agent-os.mjs";

export default {
  async fetch(request, env) {
    if (!env.AGENT_OS_ORIGIN) return new Response(null, { status: 503 });
    const viaTunnel = (url, init) => env.AGENT_OS_ORIGIN.fetch(url, init);
    return await routeAgentOS(request, env, viaTunnel) ?? new Response(null, { status: 404 });
  },
};
