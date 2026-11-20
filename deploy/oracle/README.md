# Oracle staging origin

The Oracle VM is the candidate persistent host. A prior ARM64 pilot ran under a repository-scoped runner account and wrote its own SQLite database. Qualify the VM through its administrator connection before reserving paths or starting services. The units in this directory use separate staging service accounts, releases and databases. The existing GitHub runner and monitor retain their own users, units and state.

## Inspect the host

From an approved operator session on the VM, run `python3 deploy/oracle/inspect-host.py --oci --expected-host "$EXPECTED_HOST" --pilot-db "$PILOT_DB"` from a reviewed checkout, with the host name and pilot DB path from your inventory. The optional OCI check reads only the instance display name, region and shape from IMDSv2. It reads OS and kernel versions, CPU, available memory, free disk, filesystem type, unit status, presence of the historical pilot database, staged package metadata and listener scope. A null value means the check could not establish the result. An empty listener list means no TCP listener on that port at inspection time. Verify the instance name, region, private network and persistent volume in the authenticated OCI console. Local socket observations cannot establish OCI ingress rules.

Reserve `127.0.0.1:18765` for the kernel and `127.0.0.1:12026` for the web service only after checking they are free. Confirm the two proposed users, unit names and paths are unused or belong to this exact staging installation. Keep the checkout, venv, unit files and configurations outside runner-writable directories. No Docker or gVisor service is needed for the signed read-only echo/add operator.

For a host with the units, venv and public pins already installed, continue with [first commissioning](COMMISSIONING.md).

## Prepare the two services

Use a reviewed checkout of the intended PR SHA on Ubuntu 24.04 ARM64. The host administrator runs the following on the qualified staging host. Use an approved Python package source or wheelhouse and the distribution's Python 3.12 with `python3-venv`.

```sh
sudo systemd-sysusers "$PWD/deploy/oracle/accounts.conf"
sudo /usr/bin/python3 -m venv /opt/shards-agent-stage/venv
sudo /opt/shards-agent-stage/venv/bin/pip install '.[kernel]'
sudo /opt/shards-agent-stage/venv/bin/pip check
sudo deploy/oracle/install-units.sh
sudo systemd-analyze verify /etc/systemd/system/shards-stage-kernel.service /etc/systemd/system/shards-stage-origin.service
```

The installer checks for conflicting units, installs definitions without replacing files, and reloads systemd. Service startup is a separate operator action. Protect the venv and its ancestors against writes by either service, the runner and the monitor. Keep the source checkout under administrator control when installing as root.

Supply **existing authorised staging materials** under `/etc/shards-agent-stage` (root-owned, traversable by the services, writable only by root). The CI fixture is exclusively for disposable hosted VMs.

| File | Contents and permissions |
| --- | --- |
| `kernel.env` | Root-owned 0600. Systemd environment entries for `SHARDS_KERNEL_API_KEY`, `SHARDS_KERNEL_AGENT_AUTH_PEPPER` and pinned `SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX`. |
| `operator.json` | Independently signed, current v2 operator policy. Set its port to 18765 and audit DB to `/var/lib/shards-stage-kernel/audit.sqlite3` before signing. Scope the enrolled web actor to its approved read-only tools. Root-owned, group `shards-stage-kernel`, mode 0440. |
| `origin.env` | Root-owned 0600. Set `KERNEL_AUDIENCE` to the signed kernel ID, `STAGING_PUBLIC_ORIGIN` to the exact browser HTTPS origin without a trailing slash, `CF_ACCOUNT_ID`, an existing scoped `CF_WORKERS_AI_TOKEN`, `SHARDS_KERNEL_AGENT_TOKEN` and `SHARDS_EDGE_ASSERTION_SECRET`. |
| `authority.hex` | Pinned **public** Agent OS verifier. Install as root, mode 0444, inside the root-owned configuration directory. The service account can read the verifier and cannot replace it or change its permissions, including outside the unit. |
| `bundles/` | Root-managed directory traversable by `shards-stage-web`. Exact-call envelopes named by their argument digest and referenced permit files must be regular files owned by `shards-stage-web`, mode 0600. Preserve the absolute permit path bound into each signed bundle. Start with an empty directory until a real grant is issued. |

The issuer holds the private keys independently. The kernel accepts signed policies by default. It stores its ledger separately from the web database at `/var/lib/shards-stage-web/agent.sqlite3`. Systemd creates both state directories at mode 0700. Persist them on local durable storage. Back up the databases consistently using SQLite's online backup mechanism. Investigate any interrupted job before restoring or accepting new work. Never reissue a permit to resolve an unknown outcome.

Once the staging host, signed policy and credentials have been verified, start `shards-stage-kernel.service` and `shards-stage-origin.service` through systemd. The units support boot enablement on that staging host. Rerun the inventory, check both units are active and both ports are loopback-only. The kernel health read should return 200 and an unsigned local read of `/agent-os/` should return 403. In an operator-controlled restart exercise, compare the original receipt and check a consumed grant and assertion remain refused.

## Private ingress

For the existing Oracle staging tunnel, use the [private HTTPS installation, checks, rollback and Cloudflare handoff](https/README.md).

Use an isolated Access application and staging hostname for the browser. The Oracle-specific Worker verifies its Access JWT and forwards only mounted Agent OS requests over a Workers VPC service binding named `AGENT_OS_ORIGIN`. A missing binding returns 503. A failed private request never retries over public fetch. The VM's connector makes an outbound tunnel connection. It needs no public DNS record for the origin and no inbound OCI rule for the two service ports.

Bind the VPC service to an approved private HTTPS listener reachable by that tunnel. Use full certificate verification, the matching internal hostname and the appropriate trusted CA. The TLS terminator forwards only `/agent-os/` to the loopback web port, preserving the signed headers, browser Origin, cookies and redirect responses. The kernel port stays local. Set `ORIGIN_BASE_URL` to that internal HTTPS origin. The staging Worker also needs `ACCESS_TEAM_DOMAIN`, the staging `ACCESS_AUD` and `ORIGIN_ASSERTION_SECRET` matching the origin. The Python origin uses Workers AI by REST with its own scoped credential. The production AI and MCP bindings are independent.

The checked-in Wrangler file has no route or binding ID. An offline build needs no Cloudflare credentials.

```sh
node --test deploy/cloudflare/worker.test.mjs
npx --yes wrangler@4.165.0 deploy --config deploy/oracle/wrangler.toml --dry-run --outdir /tmp/shards-oracle-stage-bundle
```

Hosted acceptance requires the real isolated VPC service, tunnel, verified TLS endpoint, Access audience, hostname and secrets within approved resources. The Workers VPC open beta is free across Workers plans at the time of writing. Standard Worker request and compute allowances still apply. No production routing or MCP gateway binding is needed for this staging path. [VPC setup](https://developers.cloudflare.com/workers-vpc/get-started/) · [Private origin TLS](https://developers.cloudflare.com/workers-vpc/configuration/vpc-services/) · [Pricing](https://developers.cloudflare.com/workers-vpc/platform/pricing/)

## Chromebook

Use the Linux environment for independent verification or a recovery rehearsal when it is available. Transfer a public verifier and a sanitised signed test artifact, or restore a consistent backup to a private disposable database. Offline verification requires no inbound connection. A cross-host browser test needs outbound HTTPS and an authorised staging Access identity. Keep signing keys with their designated issuer, keep Oracle as the sole writer to its live databases, and leave failover manual.
