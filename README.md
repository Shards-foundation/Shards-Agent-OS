# Shards Agent OS

**Status: v0.2.0 experimental, single-host reference runtime.** A Python application-level operating environment built on [Shards-Kernel](https://github.com/Shards-foundation/Shards-kernel), not a hardware operating system or an independently certified agent sandbox.

Shards-Kernel retains the independent execution authority. Shards Agent OS manages _when_ approved operations are attempted, stores local operator-controlled memory, records local agent and device metadata, and stops accepting new work when an operator halts dispatch. It does **not** sign permits, run unrestricted tools, replace the host operating system or bypass Shards-Kernel. Its upstream signed local operator currently executes only `echo` and `add`.

## Implemented and verified

| Subsystem | Operational boundary |
|---|---|
| Scheduling | Persistent one-shot due-time jobs, atomic SQLite claims, a polling `serve` worker and maximum running-job quota |
| Execution | Delegation solely through Shards-Kernel's official local `mcp-call` CLI with independently issued signed permits |
| Interrupts | Durable local halt/resume latch stops **new claims**, and cancellation is allowed only for pending jobs; running tool calls cannot be preempted |
| Memory | Operator-only typed JSON records (working/episodic/semantic/procedural labels), partitions, provenance, TTL, deletion and optimistic version checks; no vector search or learned reasoning |
| Device / agent directory | Disabled-by-default device capability inventory and unauthenticated metadata directory; **no device execution** and **no agent authentication** are provided by these records |
| Recovery | Never automatically retries an ambiguous, timed-out or crashed operation; preserves `RUNNING` / `UNKNOWN` for operator reconciliation |
| Observability | Sanitised job states, counts and control status; does not replace Shards-Kernel's hash-chained audit ledger |

This project intentionally does not offer cron-triggered unapproved execution: kernel permits are valid only for their exact actions, have short validity windows, and are single-use. Each new scheduled execution requires its own independent authorisation.

## Install

Use Python 3.11+ and a private POSIX workstation/server. Until the Shards-Kernel PyPI publishing incident is resolved, the `kernel` extra pins immutable Shards-Kernel source commit `4d521d6aa3c523bdea905de50f50be4133321020`. This is a temporary **immutable Git source pin**, not proof that PyPI 0.1.2 is available.

```bash
python -m pip install -e '.[kernel]'
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

## Architecture and operational limits

See [architecture](docs/ARCHITECTURE.md), [operator runbook](docs/OPERATIONS.md) and [security boundaries](docs/SECURITY.md).

- Device drivers, operating-system memory management, hardware interrupts, multi-host orchestration, arbitrary shell/network/wallet tools, semantic vector retrieval, privileged physical devices and agent LLMs are **not shipped**.
- The database is local SQLite mode `0600` with WAL and synchronous full commits; the host, state directory, credentials and SQLite files must still be protected by OS-level controls. There is no encrypted memory store or independently anchored event ledger.
- `halt` stops new scheduling claims but does **not** revoke a Shards-Kernel permit or abort external side effects. `resume` never revives a halted kernel instance.
- If the worker crashes after claiming a job, it remains `RUNNING` and consumes capacity. Manual reconciliation with **independently trusted kernel evidence** is required. No automatic retries occur.
- Intended for a local trusted operator. There is no public API or Internet-accessible service in this project.

**License:** [Boost Software License 1.0](LICENSE), as selected for this repository. Shards-Kernel remains independently MIT licensed.
