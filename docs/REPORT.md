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

### Safe output creation

By default the output must **not already exist**. The file is created
atomically with `O_CREAT | O_EXCL | O_NOFOLLOW`, so an existing report, a
symbolic link or a hard link to the source database is refused before anything
is written. The source SQLite database is never a valid output target: even
when it is reachable through a different path or a hard link (same
`st_dev`/`st_ino`), the write is rejected. On any failure — validation, write
error or interruption — the partially created file is unlinked and the earlier
state is preserved.

To intentionally refresh an existing report, pass `--overwrite`. It still
refuses symlinks and the database itself, and replaces the target atomically
via a `0600` temporary file in the same directory followed by `os.replace`, so
a reader never observes a partial file.

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
| Redacted diagnostics | Raw sandbox error text is never exported. It is matched against a fixed allowlist of coarse categories (`TIMEOUT`, `PERMISSION_DENIED`, `UNAUTHORISED`, `INTEGRITY_MISMATCH`, `IMAGE_NOT_FOUND`, `PATH_NOT_FOUND`, `NOT_FOUND`, `RESOURCE_LIMIT`, `TERMINATED`, `CANCELLED`, `BROKER_UNAVAILABLE`, `UNCLASSIFIED`); unmatched text becomes `UNCLASSIFIED`. Embedded credentials, absolute paths and workload arguments cannot leak. |
| No raw output | Sandbox `stdout`/`stderr`, workload fingerprints and exit payloads beyond decision, exit code, duration and the diagnostic category are omitted. |
| Escaped display values | Every interpolated value is HTML-escaped, so a malicious halt reason, schedule name or stored error cannot inject markup or script. |
| Offline | No CDNs, no `<link>`/external `<script src>`, no fonts, no analytics. The only script is a small inline theme toggle that carries no data. |
| Private output | The report is created with `O_CREAT`/`O_EXCL`/`O_NOFOLLOW` as a `0600` regular file. Existing targets, symlinks and hard links to the database are refused. |
| Fail-closed reads | Optional tables are probed via `sqlite_master`. A genuinely absent table renders as empty; corruption, lock timeouts or malformed queries raise an error instead of being silently reported as empty. |
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
python -Werror::ResourceWarning -m unittest tests.test_report -v
```

The tests cover: status/halt summarisation, empty states, read-only guarantees
(state is byte-for-byte identical before and after, and the execution entry
points are patched to fail if ever called), HTML/script-escaping of malicious
values, absence of permits/arguments/output, offline self-containment,
`0600` output permissions, symlink refusal, and the CLI contract.

Regression tests also prove that the database cannot be destroyed: an existing
output is refused without being touched, the database path itself is refused,
a hard link to the database is refused both by default and under
`--overwrite`, `--overwrite` still replaces an ordinary report atomically, a
corrupt database surfaces a clean structured JSON error with exit code `2`
rather than a traceback, genuinely absent optional tables render as empty while
a missing `control` table is an error, and sandbox error text is reduced to an
allowlisted category. The theme toggle is verified by a headless DOM
interaction test that asserts the click handler is attached after the
document is parsed.
