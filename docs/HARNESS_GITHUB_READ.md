# Harness bridge: durable read-only GitHub inspections

**Status:** experimental single-host adapter. This bridge does not extend the signed-v2 kernel operator's supported tool list, and never grants a new permission.

## Trust boundaries

The existing echo/add jobs still require independently issued signed-v2 permits through the Shards-Kernel operator.

A github.list_workflow_runs observation uses the already implemented Shards GitHub Maintenance Agent. That monitor's StrictKernel integration uses a same-process ephemeral HMAC issuer. This is appropriate only for the existing read-only pilot and is not independently authorised for GitHub writes, deployments, wallets, or secrets access.

The token is held solely by the monitor's fixed GitHub GET handler. The harness stores repository names, summary reports and audit roots, never token values. The observer takes an injected local Python callback: this is **trusted operator code, not a sandbox**.

## Usage

Install the separately maintained GitHub agent and Shards Agent OS on the same trusted host, with the kernel extra.

    from shards_agent_os.harness import create_task, refresh_task
    from shards_agent_os.harness_read import release_read_step, run_read_job
    from shards_github_agent.github_read import GitHubReadClient
    from shards_github_agent.kernel_agent import inspect_once
    import os

    db = "/absolute/private/state/jobs.sqlite3"
    repository = "Shards-foundation/Shards-kernel"
    task_id = create_task(db, name="Inspect CI", steps=[
        {"tool": "github.list_workflow_runs", "port": 0,
         "arguments": {"repository": repository}}
    ])
    job_id = release_read_step(db, task_id=task_id, ordinal=0)
    client = GitHubReadClient(repository, os.environ["GITHUB_TOKEN"])
    result = run_read_job(db, job_id=job_id,
                          inspector=lambda repo: inspect_once(repo, client.list_workflow_runs))
    print(result["status"], refresh_task(db, task_id)["status"])

The agent CLI can use this bridge through its optional persistent-state mode.

## Recovery

Task creation records intent but does not execute GitHub calls. Release atomically queues one observation. Claim atomically marks it RUNNING before invoking the trusted read-only monitor. After validating the monitor's report and replay-verifiable kernel evidence bundle, both observation and task become SUCCEEDED.

A process crash leaves RUNNING. Invalid evidence or inspector failure becomes UNKNOWN. Neither is automatically reissued. Reconcile with independent evidence and create a new observation when needed.

A SUCCEEDED snapshot now retains its verified kernel evidence bundle in the
private SQLite database **in the same transaction** as the terminal success
status. To reconstruct lost output files without another GitHub request:

    from shards_agent_os.harness_read import get_read_evidence
    verified = get_read_evidence(db, job_id)
    report, evidence = verified["report"], verified["evidence"]

The GitHub Maintenance Agent exposes `--recover-task-id` for this same
offline export after the matching integration is installed. Persisted evidence
is bounded to 512 KiB per observation, replay-verified on read, and stored in
the protected local DB. It is **not** independently anchored proof; operators
should export and retain a separate evidence artifact if stronger attestations
or independent review are required. Earlier SUCCEEDED records created before
this schema enhancement have no persisted bundle and must fail recovery rather
than fabricate proof.

## Limitations

- Fixed operation github.list_workflow_runs, exact repository, GET only.
- port 0 identifies a local read-only adapter, never the signed operator's TCP port.
- The monitor fetches only the ten latest workflow runs, not all workflows.
- Local SQLite is durable only on a persistent volume: GitHub Actions ephemeral runners are not persistent across workflow runs.
- Bundle replay ensures internal consistency, not independently attested origin.
- No GitHub writes, LLM planner, autonomous repair, PR merges, wallet controls or remote workers.
