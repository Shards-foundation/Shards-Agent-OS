# Shards Agent OS

**Status: v0.3.0 experimental, single-host reference runtime.** A Python application-level operating environment built on [Shards-Kernel](https://github.com/Shards-foundation/Shards-kernel), not a hardware operating system or an independently certified agent sandbox.

Shards-Kernel retains the independent execution authority. Shards Agent OS manages _when_ approved operations are attempted, stores local operator-controlled memory, records local agent and device metadata, and stops accepting new work when an operator halts dispatch. It does **not** sign permits, run unrestricted tools, replace the host operating system or bypass Shards-Kernel. Its upstream signed local operator currently executes only `echo` and `add`.

## Implemented and verified

| Subsystem | Operational boundary |
|---|---|
| Scheduling | Persistent one-shot jobs, atomic claims, polling worker, running-job quota, and inert interval schedule templates that require fresh independently authorised permits per occurrence |
| Execution | Delegation solely through Shards-Kernel's official local `mcp-call` CLI with independently issued signed permits |
| Interrupts | Durable local halt/resume latch stops **new claims**, and cancellation is allowed only for pending jobs; running tool calls cannot be preempted |
| Memory | Operator-only typed JSON records (working/episodic/semantic/procedural labels), partitions, provenance, TTL, deletion and optimistic version checks; no vector search or learned reasoning |
| Device / agent directory | Disabled-by-default device capability inventory and unauthenticated metadata directory; **no device execution** and **no agent authentication** are provided by these records |
| Recovery | Never automatically retries an ambiguous, timed-out or crashed operation; preserves `RUNNING` / `UNKNOWN` for operator reconciliation |
| Observability | Sanitised job states, counts and control status; does not replace Shards-Kernel's hash-chained audit ledger |

An interval schedule **never executes automatically**. Kernel permits are single-use and constrained to an exact action. Every released occurrence requires a separately issued, freshly scoped permit. A missed occurrence is skipped, not replayed; this is deliberately not a cron issuer, and a schedule is not authorisation.

## Install

Use Python 3.11+ and a private POSIX workstation/server. The optional `kernel` extra installs the published **Shards-Kernel 0.1.3** distribution, including the cryptography and official MCP SDK dependencies. The package remains an experimental single-host reference runtime, not an independently certified OS sandbox.

```bash
python -m pip install -e '.[kernel]'
python -c 'import importlib.metadata as m; assert m.version("shards-kernel") == "0.1.3"'
python -m unittest discover -s tests -v
python -m shards_kernel demo --json
```

CI also runs an ephemeral signed real-process local operator + MCP call + replay refusal check. That CI test is evidence for the local reference path, **not** production deployment readiness.

## Run one authorised job

An **independent operator** must provision the signed v2 operator, agent-scoped token and one-use permit as specified in the [Shards-Kernel agent quickstart](https://github.com/Shards-foundation/Shards-kernel/blob/main/docs/AGENT_QUICKSTART.md). The OS runtime must not receive operator API keys, signing keys or permission to issue permits.

```bash
mkdir -m 700 -p "$HOME/.local/state/shards-agent-os"
DB="$HOME/.local/state/shards-agent-os/jobs.db"
# SHARDS_KERNEL_AGENT_TOKEN is injected privately by the trusted launcher.
shards-agent-os --db "$DB" enqueue \
  --port 8765 --tool echo \
  --arguments-json '{"text":"hello"}' \
  --permit-file /absolute/operator-issued/one-use-permit.json
shards-agent-os --db "$DB" run-once
shards-agent-os --db "$DB" list
# Or run continuously under your trusted process supervisor:
shards-agent-os --db "$DB" serve --poll 1
```

The permitted action must still be valid when due. For unattended execution you must deploy a running local operator, trusted permit-issuance workflow and host supervisor; none is automatically provisioned by installing the package.

## Interrupt / memory / inventory commands

```bash
shards-agent-os --db "$DB" halt --reason 'operator maintenance'
shards-agent-os --db "$DB" status
# Resume only after operator reconciliation of any outstanding RUNNING/UNKNOWN jobs.
shards-agent-os --db "$DB" resume

shards-agent-os --db "$DB" memory-put \
  --namespace ops --kind working --key release_note \
  --value-json '{"state":"review"}' --provenance operator --ttl-ms 3600000 --expected-version 0
shards-agent-os --db "$DB" memory-get \
  --namespace ops --kind working --key release_note
shards-agent-os --db "$DB" memory-purge-expired

shards-agent-os --db "$DB" agent-enroll --actor agent-alpha --tools echo
shards-agent-os --db "$DB" capability-register --id camera.front --kind camera
shards-agent-os --db "$DB" inventory
```

**The directory is not a security principal issuer.** `agent-enroll` stores operator notes only; it does not enrol an agent in Shards-Kernel's signed policy. `capability-register` never activates a driver. No CLI input is accepted as a signed permit or an authenticated external device execution.

## Experimental Linux sandbox executor

A first gVisor-backed workload executor is available to **trusted local operators** through the Python module `shards_agent_os.sandbox_executor`. It launches explicitly configured, digest-pinned OCI workloads with network, filesystem, process and resource restrictions. See [sandbox executor and real Linux tests](docs/SANDBOX_EXECUTOR.md). The optional **local MCP governance adapter** can register `sandbox.exec` in a separately configured StrictKernel with public-only Ed25519 permit verifiers. A correctly signed one-use permit is required for an execution request. This is **not** a remotely authenticated or production-hardened sandbox service: host-process identity separation, durable audit/recovery, and a deployed operator remain necessary.

## Durable sandbox operator (Linux, experimental)

A separately supervised, trusted host may launch the **`shards-agent-os-sandbox`** local stdio MCP server. It uses the pinned public Ed25519 verifier, single-writer locked private SQLite audit ledger, persistent clock high-water mark, and the already-governed `sandbox.exec` handler. Signed single-use permits remain rejected after operator restart. See [sandbox runtime and operator deployment](docs/SANDBOX_EXECUTOR.md).

On restart, the trusted operator also recovers **only its own** labelled
orphaned gVisor containers under the private audit lock. Recovery is journalled
before forced cleanup and fails closed on uncertain outcomes; it never retries
an interrupted workload. The operator identity must be exclusive per daemon.

**Do not give an untrusted agent the operator's OS identity or Docker socket.** The MCP transport is local stdio, not an internet-facing API or an authentication perimeter; the host launcher must enforce separate identities, fixed command/configuration, secret separation and process supervision. Remote, multi-user production execution remains unsupported.

## Linux Unix sandbox broker (experimental host service)

A dedicated Linux operator account can now run the long-lived
**shards-agent-os-broker** service. It accepts signed `sandbox.exec` requests
over a local Unix socket and authenticates the actual connecting Linux UID via
`SO_PEERCRED` before reading an untrusted request. Its caller does **not**
receive the operator UID, signing key or Docker socket.

The accompanying **shards-agent-os-sandbox-call** CLI submits one permit-bound
request from an unprivileged agent. A systemd service template and a
[host deployment runbook](docs/SANDBOX_HOST_DEPLOYMENT.md) describe strict
identity, socket, state and audit separation. CI exercises the real cross-UID
protocol and gVisor runtime. The host example still uses a root-equivalent
trusted Docker service account and **has not been deployed**; this is not
internet-facing or generally multi-tenant production infrastructure.

## Architecture and operational limits

See [architecture](docs/ARCHITECTURE.md), [operator runbook](docs/OPERATIONS.md) and [security boundaries](docs/SECURITY.md).

- Device drivers, operating-system memory management, hardware interrupts, multi-host orchestration, arbitrary shell/network/wallet tools, semantic vector retrieval, privileged physical devices and agent LLMs are **not shipped**.
- The database is local SQLite mode `0600` with WAL and synchronous full commits; the host, state directory, credentials and SQLite files must still be protected by OS-level controls. There is no encrypted memory store or independently anchored event ledger.
- `halt` stops new scheduling claims but does **not** revoke a Shards-Kernel permit or abort external side effects. `resume` never revives a halted kernel instance.
- If the worker crashes after claiming a job, it remains `RUNNING` and consumes capacity. Manual reconciliation with **independently trusted kernel evidence** is required. No automatic retries occur.
- Intended for a local trusted operator. There is no public API or Internet-accessible service in this project.

**License:** [Boost Software License 1.0](LICENSE), as selected for this repository. Shards-Kernel remains independently MIT licensed.

## Interval scheduling (v0.3.0)

Create a recurring **intent** without issuing a permit or executing a tool:

```bash
shards-agent-os --db "$DB" schedule-add --name heartbeat \
  --every-ms 3600000 --window-ms 60000 --port 8765 \
  --tool echo --arguments-json '{"text":"heartbeat"}'
shards-agent-os --db "$DB" schedule-list
shards-agent-os --db "$DB" schedule-due
```

When a template becomes due, an **independent** trusted operator must issue an unexpired
single-use signed permit for the exact action/arguments. Copy its `schedule_id`
from `schedule-list` and use:

```bash
shards-agent-os --db "$DB" schedule-release <schedule-id> \
  --permit-file /absolute/path/to/fresh-independent-permit.json
shards-agent-os --db "$DB" run-once
```

`<schedule-id>` above is a placeholder, not an angle-bracket literal to type.
For downtime recovery use `schedule-skip <schedule-id>` to advance expired
windows without consuming any permit or queuing work. Disable a template with
`schedule-disable <schedule-id>` and re-enable with `schedule-enable <schedule-id>`.
Both template state and the SQLite schedule-clock high-water mark persist across
restarts. A clock rollback fails closed until the operator investigates the
underlying clock/state discrepancy. Host clock integrity and local DB trust
are *not* cryptographic time guarantees.

Schedule release is a deliberate operator action and does **not** automatically
create signing credentials, run an LLM, access devices or bypass Shards-Kernel.
The same permit file path is rejected for repeated template releases, but only
Shards-Kernel verifies permit signatures and cryptographic replay constraints.
The private state directory must be mode 0700 to protect SQLite WAL files.
