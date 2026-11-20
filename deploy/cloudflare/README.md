# Agent OS on the Shards hub

The hub owns the workspace, chat, model catalogue and agent registry. Its custom domain is `agents.shardsinc.co.uk`. Version 12 serves four models through `AI` and sends registry requests through `MCP_GATEWAY` to `shards-mcp-edge`. The Agent OS integration adds a server-rendered UI under `/agent-os/`. The origin owns sessions, model calls, signed dispatch and receipts.

## Bundle and verify locally

From the repository root, install the kernel extra in a virtual environment. Node 22 or later runs the Worker tests and the cross-language assertion contracts.

```sh
python -m pip install -e '.[kernel]'
node --test deploy/cloudflare/worker.test.mjs
python -m unittest discover -s tests -v
npx --yes wrangler@4.165.0 deploy --config deploy/cloudflare/wrangler.toml --dry-run --outdir /tmp/shards-agent-os-staging-bundle
```

The Wrangler file builds a standalone staging entry with no routes, public preview URLs, AI or gateway bindings. The dry run is local. The governed browser flow needs a reachable HTTPS origin, an Access-protected staging hostname and its own application audience before a remote test.

## Origin prerequisites

Run the Python service on a trusted host with persistent private storage, a supervised signed Shards-Kernel 0.1.3 operator, its enrolled agent token and a configured Qwen provider. Give Agent OS the authority's public verifier and independently issued exact-call bundles. Keep the issuer's private keys outside the service. Restrict ingress to the mounted paths through an HTTPS reverse proxy or an existing secured tunnel to the loopback listener. Use the public **browser** origin for `--edge-public-origin`.

For an existing Workers AI REST credential, the origin invocation is:

```sh
shards-agent-os-agent \
  --db "$STATE_DIR/agent.sqlite3" --audience "$KERNEL_AUDIENCE" \
  --authority-public-key-file "$VERIFIER_FILE" --bundle-dir "$BUNDLE_DIR" \
  --kernel-port "$KERNEL_PORT" --host 127.0.0.1 --port 12000 \
  --mount-path /agent-os --edge-public-origin "$STAGING_PUBLIC_ORIGIN" \
  --provider workers-ai --cf-account-id "$CF_ACCOUNT_ID" \
  --provider-credential-env CF_WORKERS_AI_TOKEN
```

Use `--delegation-file` for separately authorised observation tools. The host service manager supplies `SHARDS_KERNEL_AGENT_TOKEN` and `SHARDS_EDGE_ASSERTION_SECRET`. A local Transformers installation or a configured OpenAI-compatible Qwen provider can also serve the origin. The hub's AI service binding is available only inside its Worker.

Configure the isolated edge with the following settings via its environment's secret/configuration store.

| Setting | Value |
| --- | --- |
| `ACCESS_TEAM_DOMAIN` | Staging team's hostname ending in `.cloudflareaccess.com` |
| `ACCESS_AUD` | The staging Access application's audience |
| `ORIGIN_BASE_URL` | The HTTPS origin endpoint, separate from the public browser URL |
| `ORIGIN_ASSERTION_SECRET` | The same high-entropy text as the origin's `SHARDS_EDGE_ASSERTION_SECRET`, at least 32 bytes |

## Compose with the hub

Use the hub's own source and deployment configuration. Import the named export alongside the hub entry. Insert the two dispatch lines **after** the existing Access and TLS checks and before its existing route dispatch. Add a link to `/agent-os/` in the workspace navigation when preparing the hub change.

```js
import { routeAgentOS } from "./agent-os.mjs";

// Inside the existing fetch(req, env) handler, after its Access and TLS checks
const governed = await routeAgentOS(req, env);
if (governed) return governed;
```

Copy both `agent-os.mjs` and its sibling `worker.mjs` to the module location used by that import. Keep the hub entry, its custom domain, models, registry dispatch, `AI` and `MCP_GATEWAY` in the hub configuration. Requests outside the mount return control to the existing handler. The staging Wrangler file has a different service name and packages only the standalone mount.

## Hosted acceptance

On an isolated Access-protected staging hostname, verify the anonymous Access challenge, then sign in as the authorised staging actor. Open `/agent-os/`, submit a question with one independently authorised read-only call and open its receipts. Match the job ID and result against the origin's persisted receipts and kernel ledger. Repeat the exact call with the consumed grant and confirm refusal with no second job. Check the hub workspace, model catalogue, chat and registry against their staging counterparts. Restart the origin against the same private state and confirm the first receipt and replay refusal persist.

On 20 November 2026 the production hub had no origin or assertion settings and its preview URLs were disabled. Inventory identified no Agent OS staging hostname, active Cloudflare Tunnel or Pages project in the account. The Containers API reported that a paid Workers plan was required. Hosted acceptance requires an existing origin host and isolated ingress. The live gateway and the unrelated MCP staging Workers are separate services.
