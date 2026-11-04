# Local operator runbook

## Host prerequisite

Linux/POSIX environment with Python >=3.11, persistent local disk, private `0700` state directory, process supervisor, independently signed Shards-Kernel local operator and a separate permit issuer. The reference operator currently supports `echo` and `add` only.

## Startup

1. Provision and start Shards-Kernel's signed v2 operator following its own runbook. Verify loopback health from the same host. Do **not** give the Agent OS launcher the operator bearer, signing key or issuer credentials.
2. Inject an individual enrolled `SHARDS_KERNEL_AGENT_TOKEN` from your secret store into the Agent OS worker runtime. Never put this token in shell history, `.env` committed to Git, CLI flags or logs.
3. Install this app with `python -m pip install -e '.[kernel]'`, create private state, enqueue one signed permit-bound `echo` job, then run `shards-agent-os --db "$DB" run-once`.
4. When the one-shot path works and has a verified kernel receipt, supervise `shards-agent-os --db "$DB" serve --poll 1 --max-running 1` on the trusted host. It does not fork or self-install as a system service.

## Shutdown and incident response

- `shards-agent-os --db "$DB" halt --reason 'maintenance'` prevents *new* jobs from being claimed. This is **not a hard interrupt** of already running work.
- Stop the worker with SIGTERM. A separate kernel operator may continue processing an in-flight request; check its audit/evidence before considering any retry.
- Inspect `status` and `list`. Any stale `RUNNING` or `UNKNOWN` result requires manual investigation; never duplicate the same permit or action to guess an outcome.
- `resume` clears the local dispatch latch only; it is not a cryptographic authorization and cannot reset a HALTED Shards-Kernel instance.

## Backups and disaster recovery

Back up SQLite with SQLite's online backup API rather than copying a live WAL file. Treat backups as sensitive plaintext and protect them with independent host-level encryption/access control. The OS database does not replace kernel's separate evidence ledger or external trusted checkpoints. Restore on a private host, review outstanding RUNNING jobs before resuming, and never reissue permits on the basis of a backup alone.

## Scope

No deployment host, KMS/HSM, secret store, reverse proxy, public endpoint, cron installer or unattended permit issuer is provisioned by this repository. Sensitive production execution requires a separate deployment exercise with independent verification.
