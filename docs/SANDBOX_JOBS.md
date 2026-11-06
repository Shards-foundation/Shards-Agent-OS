# Durable sandbox jobs: Agent OS -> permit -> gVisor

This is the first scheduled execution workflow for sandbox.exec in Shards Agent OS.
It is separate from the legacy echo/add loopback MCP scheduler but shares
the same private SQLite database, HALT latch and outstanding-job quota.

## Trust and execution path

1. A separate, trusted offline approver inspects exact workload JSON, then
   issues a short-lived, one-use Ed25519 v2 permit using an encrypted signing
   key. Keep that signer off the sandbox host.
2. An unprivileged agent stores exactly matching arguments.json and permit.json
   in owner-only 0600 files. This agent has no Docker or signing-key access.
3. Agent OS queues the nonsecret workload, permit FILE PATH, broker socket
   and pinned operator UID. It never puts permit content into SQLite.
4. When due, the worker durably marks the job RUNNING before reading the
   private permit and calling the SO_PEERCRED-authenticated Unix broker.
5. Shards-Kernel verifies the signature, parameters and actor, consumes the
   permit, runs one image-digest-pinned gVisor workload and audits it.
6. Agent OS records a bounded, correlated receipt. Unverifiable effects are
   UNKNOWN and are never automatically replayed.

## Practical deterministic calculation

Here is an approved-workload candidate that computes a count, total and
average using BusyBox awk. Replace the image placeholder with a genuine
digest from a trusted preloaded Docker image and have the human approver
inspect ALL of the arguments before signing.

~~~json
{
  "image": "busybox@sha256:REPLACE_WITH_VERIFIED_PRELOADED_DIGEST",
  "argv": [
    "/bin/awk",
    "BEGIN { a[1]=12; a[2]=18; a[3]=24; for (i=1; i<=3; i++) s+=a[i]; printf \"count=3 total=%d average=%.1f\\n\", s, s/3 }"
  ],
  "timeout_seconds": 20,
  "memory_megabytes": 256,
  "cpu_millicores": 500,
  "pids_limit": 32
}
~~~

This workload has no network access, no host mounts, a read-only root,
resource budgets and verified container cleanup. It is actual computation,
not a hard-coded success response.

## Enqueue and execute

Run the following under the unprivileged agent Linux UID that is configured
as the broker's only authorised peer. Use a private, agent-owned 0700
directory for Agent OS state. The signed permit is first created OFFLINE
using the procedure in SANDBOX_HOST_DEPLOYMENT.md, and copied back to
the agent-owned 0600 permit.json file.

~~~bash
export OS_DB=/home/shards-agent/work/agent-os.sqlite3

shards-agent-os --db "$OS_DB" sandbox-enqueue \
  --operator-uid "$(id -u shards-sandbox)" \
  --arguments-file /home/shards-agent/work/arguments.json \
  --permit-file /home/shards-agent/work/permit.json

shards-agent-os --db "$OS_DB" sandbox-run-once --max-running 1
shards-agent-os --db "$OS_DB" sandbox-list
shards-agent-os --db "$OS_DB" status
~~~

For supervised dispatch of due sandbox jobs (run as the agent UID):

~~~bash
shards-agent-os --db "$OS_DB" sandbox-serve \
  --poll 1 --timeout 150 --max-running 1
~~~

Enqueue may also accept a UTC millisecond due time through --run-at-ms.
The offline issuer currently restricts permit TTL to 10–300 seconds.
Acquire approval close to execution time: a distant scheduled event cannot
reuse today's short-lived permit. Enqueue returns authorised=false because
queue admission is never cryptographic authorisation.

## Failure, halt and restart

- Existing Agent OS halt blocks future jobs from both schedulers.
- Both workers count outstanding RUNNING jobs toward one shared quota.
- sandbox-cancel affects PENDING only.
- sandbox-reconcile-unknown requires an incident ID and moves a stuck
  RUNNING claim to UNKNOWN ONLY after independent operator investigation.
  It never resubmits the action.
- SUCCEEDED requires exact workload SHA-256 correlation, exit code zero,
  reported EXITED status and confirmed container cleanup.
- FAILED requires confirmed cleanup of a nonzero, timed-out or
  output-limited execution; no automatic retry.
- DENIED is an explicit broker authorisation refusal; UNKNOWN is a
  missing, ambiguous or unverified result and must not be retried blindly.
- Durable results store up to 8 KiB per output stream plus full stream hashes
  and truncation metadata; neither permit bytes nor private paths are
  included in public job listings.

Normal Agent OS serve still runs legacy loopback MCP jobs; sandbox-serve
runs sandbox.exec jobs against the dedicated broker. Neither job queue
issues permits or provides agent access to Docker.

## Acceptance

The installed Linux CI host-pilot now verifies real scheduling from the
unprivileged agent account through systemd, SO_PEERCRED, a consumed signed
permit and runsc. It confirms deterministic real output, a stored
SUCCEEDED receipt, DENIED replay in a different queued job, no automatic
retry, private audit state and no agent access to Docker.
