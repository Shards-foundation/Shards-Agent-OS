# Task review and disposition contract

**Status: NOT IMPLEMENTED.** This document records the boundary between
execution authorisation and independent task review, and the minimal
separately gated contract a future implementation must satisfy. No code in
this repository currently reviews, approves, rejects, preserves or claims an
external task.

## Why the distinction matters

The runtime proves one narrow property today: an independently signed artefact
authorises an exact execution. That is *execution authorisation*.

It is **not** a task-review judgment. The following must never be presented as,
or converted into, a review verdict:

- a signed tool permit, a kernel `ALLOW`/`DENY` receipt, or a one-use grant;
- a turn status (`RUNNING`, `SUCCEEDED`, `DENIED`, `FAILED`, `UNKNOWN`);
- a harness task status (`WAITING_PERMIT`, `QUEUED`, `RUNNING`, `SUCCEEDED`,
  `DENIED`, `UNKNOWN`, `CANCELLED`);
- a model reply or model-generated recommendation;
- a Shards MCP message/task record or transport acknowledgement.

A model may propose. It may never approve its own proposal, mint a permit, or
become the reviewer of record.

## Current state at `4ce129d50a85027b653fec074730df70307258b7`

| Product operation | Classification | Evidence |
| --- | --- | --- |
| External task intake | **ABSENT** | The only task constructor is `harness.create_task` (`src/shards_agent_os/harness.py:96`), which accepts a local name and step list. The web surface exposes only `/`, `/api/health`, `/auth/callback`, `/auth/exchange`, `/logout`, `/ask` and `/turn/<id>` (`src/shards_agent_os/web_server.py:525-578`). No transport consumes an external task or review request. |
| Authenticated claim | **ABSENT for review tasks** | Execution jobs are claimed atomically (`src/shards_agent_os/scheduler.py:187`), and the read adapter claims an observation job (`src/shards_agent_os/harness_read.py:107`). Neither is a claim of a review task, and no claim record names a reviewer. |
| Independent reviewer assignment | **ABSENT** | No reviewer, assignee or verdict authority exists in `src/`. `offline_approver` issues an execution permit for an already-approved digest (`src/shards_agent_os/offline_approver.py:145`), not a review decision. |
| Evidence collection | **IMPLEMENTED BUT UNPROVEN as review evidence** | The read adapter collects one fixed read-only GitHub observation and replay-verifies a kernel evidence bundle (`src/shards_agent_os/harness_read.py:66-104`). Its own doc states that replay proves internal consistency, not independently attested origin (`docs/HARNESS_GITHUB_READ.md`). It produces no reviewer evidence package. |
| `APPROVE` / `REQUEST_CHANGES` / `DENY` decision | **ABSENT** | Those tokens do not appear in `src/`. The only decision set is the kernel execution decision `{"ALLOW", "DENY"}` (`src/shards_agent_os/report.py:60`). Turn denial is recorded as `DENIED` (`src/shards_agent_os/agent_loop.py`). |
| `PRESERVE` / `REJECT` task disposition | **ABSENT** | Neither disposition exists. Harness states are `WAITING_PERMIT`, `QUEUED`, `RUNNING`, `SUCCEEDED`, `DENIED`, `UNKNOWN`, `CANCELLED` (`src/shards_agent_os/harness.py:17`). Turn states are `RUNNING`, `SUCCEEDED`, `DENIED`, `FAILED`, `UNKNOWN` (`src/shards_agent_os/agent_state.py:22`). |
| Durable audit / recovery | **IMPLEMENTED + TESTED** | `agent_state.recover_incomplete_turns` (`src/shards_agent_os/agent_state.py:246`), `harness.refresh_task` (`src/shards_agent_os/harness.py:181`), `harness_read.reconcile_read_unknown` (`src/shards_agent_os/harness_read.py:237`) and the read-only recovery report. Tests: `tests/test_agent_process_acceptance.py:189`, `tests/test_harness_process_recovery.py`, `tests/test_recovery_report.py`. |
| Handoff to kernel execution | **IMPLEMENTED + TESTED** | `agent_loop._kernel_dispatch` (`src/shards_agent_os/agent_loop.py:145`) and `harness.release_step` (`src/shards_agent_os/harness.py:189`). Tests: `tests/test_agent_governed_e2e.py:82,105,132`, `tests/test_live_kernel_integration.py`, `tests/test_harness_live_kernel.py`. |

Consequently, a review of an existing item such as PR #26 through this
repository is **ABSENT**. A GitHub bot `COMMENTED` review, a kernel `ALLOW`
receipt, a one-use permit, or an MCP transport acknowledgement is not a
governed Agent OS review verdict.

## Minimal implementation contract

Implement as a **separate, separately gated change**, not by extending the
execution state machine or the tool registry.

### 1. Separate identities and keys

- A review authority key domain distinct from the permit issuer, the offline
  approver and the agent token.
- A reviewer identity that is distinct from the worker that claimed the task.
  The runtime must refuse self-assignment and self-review.
- The model has no reviewer key and no path to one.

### 2. Separate durable tables

Never reuse `agent_turns`, `harness_tasks` or `harness_steps`. New tables, at
minimum:

- `review_tasks` — provenance, source reference, immutable content digest,
  state.
- `review_claims` — task, claimant, lease expiry, one active claim.
- `review_evidence` — content-addressed evidence items and a root digest.
- `review_verdicts` — reviewer, epoch, verdict, evidence root, signature.
- `review_dispositions` — derived disposition, actor, timestamp.
- `review_audit` — append-only, hash-chained events.

### 3. States and transitions

```
UNCLAIMED -> CLAIMED -> UNDER_REVIEW -> APPROVED
                                     -> CHANGES_REQUESTED
                                     -> DENIED
```

Disposition is derived only from a valid verdict:

- `APPROVED` -> `PRESERVE` (or explicit `REJECT` with a recorded reason);
- `CHANGES_REQUESTED` -> no disposition until the review epoch closes;
- `DENIED` -> `REJECT`.

A crash leaves `CLAIMED`/`UNDER_REVIEW` visible. Recovery may move it to
`UNKNOWN`; it must never re-execute or silently re-review.

### 4. Invariants

1. Intake records provenance and an immutable content digest; no mutable task
   body after intake.
2. Claim is atomic (`BEGIN IMMEDIATE`), owner-scoped and lease-bound; at most
   one active claim per task.
3. The reviewer of record is a distinct identity from the claimant and from
   the executing worker.
4. Every verdict binds the exact evidence root digest. Evidence is
   content-addressed and immutable.
5. A verdict is signed by the review authority and is one-per-epoch. An
   amendment creates a new epoch; prior epochs remain auditable.
6. A disposition requires a valid, current verdict. No verdict, no
   disposition.
7. A model reply is stored as input only. It is never a verdict, a permit or
   a disposition.
8. Kernel execution after review still requires its own independent permit.
   An `APPROVED` verdict is not a permit.
9. `APPROVE`/`REQUEST_CHANGES`/`DENY` and `PRESERVE`/`REJECT` must never be
   written into `agent_turns.status` or `harness_tasks.status`.

### 5. Required acceptance tests before activation

- Intake rejects an unauthenticated or unprovenanced source.
- A second concurrent claim is refused.
- A claimant cannot review its own task.
- A model reply cannot create a verdict, disposition or permit.
- A tampered evidence item invalidates the verdict binding.
- Replaying an old verdict against a new evidence root is refused.
- `CHANGES_REQUESTED` cannot produce `PRESERVE`.
- `DENIED` cannot produce `PRESERVE`.
- A crash between claim and verdict leaves `UNKNOWN`, never an implicit
  approval, and never replays.
- A verdict is not accepted as a kernel permit; the kernel still enforces its
  own signed permit.
- The audit chain detects deletion or reordering.

### 6. Activation gate

- Off by default behind an explicit, separately reviewed configuration flag.
- Separate signing keys, separate database migration and separate operator
  runbook.
- Independent review of the review engine itself before it is enabled.
- No production deployment, merge or credential change as part of activation.

## Explicit non-goals

- No model self-approval or model-issued permits.
- No automatic merge, deployment, GitHub write or wallet action.
- No reuse of execution statuses as review verdicts.
- No claim that a transport acknowledgement proves a task was consumed or
  reviewed.
