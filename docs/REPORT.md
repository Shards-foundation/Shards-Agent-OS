# Offline operational report (`export-report`)

`export-report` writes a **single self-contained HTML file** that summarises the
current local state of Agent OS. It is designed for a security-sensitive
operator who wants to review status on an Android phone without exposing the
runtime to a network, a CDN or a dashboard service.

```bash
shards-agent-os --db "$DB" export-report --output /absolute/path/shards-report.html
```

The command prints a small JSON summary (counts and `status: EXPORTED`) and
writes the report to `--output`.

## What the report shows

* **Point-in-time snapshot banner** — the report is explicitly labelled as a
  static export and *not* a live monitoring service.
* **Dispatch control** — the local halt latch, its reason and last update time.
* **MCP job summary** — counts of `echo`/`add` jobs by status.
* **Outstanding jobs** — `RUNNING` and `UNKNOWN` jobs from both queues, which
  are the ones that require manual operator reconciliation.
* **Sandbox job summary** — counts plus a bounded outcome table
  (decision / exit code / duration) for sandbox jobs.
* **Scheduling** — inert interval templates with interval, next due time,
  enabled state and skipped-interval count.
* **Light and dark themes** — follows the phone's system preference, with a
  manual `Theme` toggle. All styling is inline; no external assets are loaded.

Empty datasets render explicit empty-state text rather than a blank panel.

## Security properties

| Property | Implementation |
|---|---|
| Read-only | The SQLite file is opened `mode=ro` with `PRAGMA query_only=ON`. The exporter never inserts, updates, deletes, enqueues or executes a job, and cannot change the halt latch or schedule state. |
| Allowlisted fields | Only named columns are selected (`job_id`, `tool`, `status`, timestamps, schedule metadata). Permit paths, permit contents, agent bearer tokens and workload arguments are never read. |
| No raw output | Sandbox `stdout`/`stderr`, workload fingerprints and error payloads beyond a bounded, escaped note are omitted. |
| Escaped display values | Every interpolated value is HTML-escaped, so a malicious halt reason, schedule name or stored error cannot inject markup or script. |
| Offline | No CDNs, no `<link>`/external `<script src>`, no fonts, no analytics. The only script is a small inline theme toggle that carries no data. |
| Private output | The report is written as a `0600` regular file with `O_NOFOLLOW`; a symlink target is refused. |
| No creation side effect | A missing database is rejected (exit code `2`) rather than created. |

## Limitations

* The report is a snapshot. It does **not** monitor, alert, retry or reconcile;
  re-run the command for current state.
* `halt` blocks new claims only and does not preempt in-flight kernel or sandbox
  work; the report states this but cannot prove it.
* Device capability records, agent directory entries and memory values are
  intentionally **not** exported to keep the surface minimal.
* The database path is not printed; only the report's own generation time is.
* Generating the report does not change Shards-Kernel authority, permits,
  policy, authentication or execution semantics.

## Usable example

```bash
export DB="$HOME/.local/state/shards-agent-os/jobs.db"
mkdir -m 700 -p "$(dirname "$DB")"

# ... enqueue / run / halt as usual ...

shards-agent-os --db "$DB" export-report \
  --output "$HOME/shards-report.html"
# {"halted":false,"jobs":3,"output":"/home/user/shards-report.html", ... }
```

Copy the file to the phone (for example over a trusted local transfer) and open
it in any browser. It works fully offline.

## Tests

```bash
python -m unittest tests.test_report -v
```

The tests cover: status/halt summarisation, empty states, read-only guarantees
(state is byte-for-byte identical before and after, and the execution entry
points are patched to fail if ever called), HTML/script-escaping of malicious
values, absence of permits/arguments/output, offline self-containment,
`0600` output permissions, symlink refusal, and the CLI contract.
