# Temporal + Shards Agent OS: read-only durable orchestration pilot

**Status: review-only example, NOT deployed, NOT a new trust authority.**
This example lives outside `src/shards_agent_os` and does not alter any Agent OS
SQLite job semantics, signed permits, broker, worker, scheduling or releases.

## Role separation

1. **Temporal** owns durable orchestration state and a schedule of the activity.
2. **Existing Shards GitHub Agent** performs one restricted GitHub GET through
   its Shards-Kernel-governed local pilot.
3. **Shards-Kernel** authorises the existing fixed read operation; this
   example cannot authorise `sandbox.exec`, issue general permits, merge,
   send messages, change repositories or pay for a service.
4. **Human operator** reviews failures and separately authorises any write.

Temporal Activity retries are **at least once**, not exactly-once external
effects. We only retry this read-only inspection. Never automatically retry
an ambiguous Shards Agent OS `RUNNING`/`UNKNOWN` job or any non-idempotent
effect. Temporal's event history is **not** Shards-Kernel's audit ledger.

## Offline contract tests (no provider key or Temporal server)

```bash
cd examples/temporal
python -m unittest test_contracts -v
```

This validates repository pinning, data minimisation, injection-resistant
sanitisation and negative cases. It is not a Temporal cluster E2E test.

## Optional local integration (requires installed software and a trusted host)

Prerequisites:
- A local development-only Temporal Service (`temporal server start-dev`).
- Python SDK: `python -m pip install temporalio`.
- Install the existing `Shards-foundation/shards-github-agent` package into
  the same virtual environment from a reviewed, pinned source revision.
- A GitHub bearer scoped to read Actions for one repository, injected through
  a private secret manager / owner-only host environment.

```bash
cd examples/temporal
export SHARDS_TEMPORAL_REPOSITORY=Shards-foundation/Shards-kernel
# GITHUB_TOKEN supplied privately by the trusted launcher; do not paste it.
python runner.py worker  # terminal/service A: supervised Worker
python runner.py once    # terminal B: one read-only inspection
python runner.py create-paused-schedule
```

The schedule is **PAUSED by default**. After confirming the host, token scope,
resource capacity, expected failure reporting and no paid billing, the operator
can enable it deliberately:

```bash
export SHARDS_TEMPORAL_SCHEDULE_APPROVAL=I_APPROVE_LOCAL_READ_ONLY_TEMPORAL_SCHEDULE
python runner.py unpause
```

The schedule then requests a GET-only inspection every six hours from the
local Temporal Worker, provided the Worker and Service are actually running.
No notifications or downstream writes are implemented.

## Production blockers

- Temporal CLI development server is **not production infrastructure**.
- Do not deploy a production Temporal Service on an existing shared
  GitHub Actions runner or privileged sandbox broker without host isolation
  and explicit review. Self-hosting requires capacity, durable server storage,
  network/TLS/authentication controls, backup and supervised Workers.
- Temporal Cloud trial credits are **not a permanent free tier**. No paid
  endpoint, account, API token, namespace or billing is created here.
- This example uses the existing GitHub agent's explicitly documented
  ephemeral **same-process HMAC read-only permit**. That does not satisfy
  separate independent issuance for writes.
- User's ChatGPT plugin authorisations are NOT inherited by Temporal Workers.
  Gmail, Calendar, Activepieces or other app integrations require their own
  authorised connector credentials or a formally authenticated gateway.
- Establish live Temporal replay, crash/restart, worker disconnect, duplicate
  schedule prevention and idempotency checks before claiming unattended use.

Sources:
- https://docs.temporal.io/develop/python
- https://docs.temporal.io/production-deployment
- https://docs.temporal.io/develop/python/workflows/schedules
- https://github.com/temporalio/samples-python
