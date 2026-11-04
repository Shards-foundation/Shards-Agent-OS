# Shards Agent Harness — first integration slice

**Status:** experimental, locally tested. Durable, sequential multi-step plans using
the existing Shards Agent OS scheduler and its Shards-Kernel-governed execution path.

This harness is a separate orchestration module inside the Agent OS repository,
rather than a second independently implemented scheduler. It can be extracted
into a standalone distribution behind a versioned queue API later.

## Architecture

    Operator -> Harness plan -> independently issued single-use signed permit
                -> Agent OS SQLite job queue -> Shards-Kernel local MCP operator
                -> verified OS job outcome -> Harness checkpoint reconciliation

The harness does not issue permits, authenticate agents, operate an LLM,
open GitHub PRs, or execute tools by itself. Kernel authority is unchanged.

## Create a two-step task

Use the same private 0700 state directory and SQLite database as Agent OS.

    DB="$HOME/.local/state/shards-agent-os/jobs.db"
    python -m shards_agent_os.harness_cli --db "$DB" create \
      --name "Two independently authorised steps" \
      --steps-json '[{"port":8765,"tool":"echo","arguments":{"text":"hello"}},{"port":8765,"tool":"add","arguments":{"a":2,"b":3}}]'

The command returns a task_id. Creating a task only records intent;
no execution occurs.

## Release and verify one step at a time

An independently trusted operator must create a fresh, exact, one-use permit
for step 0, using the Shards-Kernel documented signed-v2 operator process.

    python -m shards_agent_os.harness_cli --db "$DB" release "$TASK_ID" 0 \
      --permit-file /absolute/private/step-0-permit.json
    shards-agent-os --db "$DB" run-once
    python -m shards_agent_os.harness_cli --db "$DB" refresh "$TASK_ID"

Only once stage 0 shows SUCCEEDED, obtain a distinct, freshly issued permit
for step 1 and execute:

    python -m shards_agent_os.harness_cli --db "$DB" release "$TASK_ID" 1 \
      --permit-file /absolute/private/step-1-permit.json
    shards-agent-os --db "$DB" run-once
    python -m shards_agent_os.harness_cli --db "$DB" refresh "$TASK_ID"

Task state and job IDs persist. The release insert and stage transition happen
in a single SQLite transaction. A worker crash leaves RUNNING as-is;
UNKNOWN is terminal pending out-of-band operator reconciliation.
The harness never automatically replays an ambiguous operation.

## Current limitations

- Only the existing kernel-governed echo and add tools are allowed.
- Maximum 32 ordered steps. No DAG, planner, LLM, GitHub writer, wallet
  control, cloud service, cron issuer, or multi-host execution.
- This code relies on the existing Agent OS private SQLite schema.
- The signed local operator and independent permit issuer must exist separately.
- Kernel evidence is the execution authority. A harness status snapshot is
  not cryptographic proof of external side effects.
- The harness does not prevent an unrelated process from bypassing the kernel.
- Integration with a live signed-v2 operator is a separate acceptance gate.

## Regression tests

    python -m unittest discover -s tests -v

Tests cover persistence, no execution on task creation, atomic duplicate
rejection, concurrent release, sequential gates, operator halt, missing jobs,
unknown/denied/cancelled terminal state, permit path reuse, snapshot sanitisation,
invalid arguments and CLI parsing.
