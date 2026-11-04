# Shards Agent OS

**Status: v0.1.0 experimental, local-only.** An application-level agent runtime built on the independently released [Shards-Kernel](https://github.com/Shards-foundation/Shards-kernel). This is **not** a hardware operating-system kernel, distributed job scheduler, production service, or unrestricted AI-agent orchestrator.

## First working slice

- SQLite-backed one-shot scheduled jobs, durable state and atomic claim.
- Execution goes **only** through the installed `python -m shards_kernel mcp-call` client, which talks to an existing signed, loopback-only operator.
- Jobs are limited to the kernel's official `echo` and `add` tools. Each execution requires a separately issued, single-use signed permit and an enrolled agent token provided to the process by its trusted launcher.
- `PENDING -> RUNNING -> SUCCEEDED / DENIED / UNKNOWN`. Only pending jobs may be cancelled. Timeout, crash or ambiguous receipt **never causes automatic replay**; external effects may already have occurred.
- Local SQLite memory stores job state and sanitized receipts; long-term semantic/episodic memory, arbitrary devices, cron and preemptive interrupts are **not yet implemented**.

## Install

Python 3.11+ on a trusted POSIX host:

```bash
python -m pip install -e '.[kernel]'
python -m unittest discover -s tests -v
python -m shards_kernel demo --json
```

The offline Shards-Kernel demo checks the dependency; it **does not** establish an enrolled operator or validate a live scheduled MCP call.

## Run one scheduled job

An independent operator must first provision a signed v2 local operator and issue a correctly scoped single-use permit. Follow the [official agent quickstart](https://github.com/Shards-foundation/Shards-kernel/blob/main/docs/AGENT_QUICKSTART.md). Do not commit permits or credentials. The process must receive its own `SHARDS_KERNEL_AGENT_TOKEN` privately from a trusted launcher.

```bash
mkdir -m 700 -p "$HOME/.local/state/shards-agent-os"
DB="$HOME/.local/state/shards-agent-os/jobs.db"
shards-agent-os --db "$DB" enqueue \
  --port 8765 --tool echo \
  --arguments-json '{"text":"hello"}' \
  --permit-file /absolute/operator-issued/permit.json
shards-agent-os --db "$DB" run-once
shards-agent-os --db "$DB" list
```

`8765` is an illustration: use the actual configured loopback port. To schedule a later execution supply `--run-at-ms` as Unix epoch milliseconds; the operator-issued permit **must still be valid at execution time**. `run-once` processes at most one due job; use a trusted system scheduler to invoke it periodically. No credentials, private keys or signing logic are stored in this project.

## Design boundaries

The job store and signed Shards-Kernel audit ledger are separate records with different guarantees. The DB is secured to mode 0600, but it is **not** a tamper-evident audit ledger. A worker crash can leave a job in `RUNNING`; this state must be reconciled using operator evidence before any new attempt is authorised. A timeout of the CLI subprocess does not stop work already received by the separate operator.

No direct agent-to-device, agent-to-tool or bypass adapter is permitted. The OS may schedule an action, but only Shards-Kernel can authorise its execution. A real multi-agent runtime, scheduler daemon, memory subsystem and device broker belong in later independently verified milestones.
