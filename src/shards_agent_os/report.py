"""Read-only, offline, self-contained operational report exporter.

This produces a single static HTML file describing a *point-in-time* snapshot
of local Agent OS state. It is deliberately NOT a live monitoring service, has
no network calls, no CDNs, no external scripts and no runtime hot path.

Security posture:

* The SQLite database is opened read-only (``mode=ro`` plus ``PRAGMA
  query_only``).  This module never inserts, updates, deletes, enqueues or
  executes a job, and it cannot change the halt latch or schedule state.
* Every exported field is drawn from an explicit allowlist.  Permit paths,
  permit contents, agent bearer credentials, workload arguments and raw
  stdout/stderr are never read or emitted.
* All values are HTML-escaped before interpolation, so a malicious operator
  supplied halt reason or schedule name cannot inject markup or script.
* Stored sandbox error text is never exported verbatim; it is reduced to a
  coarse allowlisted diagnostic category so embedded credentials, absolute
  paths or workload arguments cannot leak into the report.
* The output file is created with ``O_EXCL`` by default, so an existing report,
  a symlink or a hard link to the database is refused without truncating
  anything.  The source database is never a valid output target.
"""
from __future__ import annotations

import html
import json
import os
import sqlite3
import stat
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .storage import PrivateConnection

# --- Field allowlists -------------------------------------------------------
# Only these columns are ever selected; everything else stays in the database.
_JOB_COLUMNS = (
    "job_id", "tool", "status", "run_at_ms",
    "created_at_ms", "started_at_ms", "finished_at_ms",
)
_SANDBOX_COLUMNS = (
    "job_id", "status", "run_at_ms",
    "created_at_ms", "started_at_ms", "finished_at_ms",
)
_SCHEDULE_COLUMNS = (
    "schedule_id", "name", "interval_ms", "next_due_ms", "window_ms",
    "tool", "enabled", "last_job_id", "skipped_intervals",
)
_CONTROL_COLUMNS = ("halted", "reason", "updated_at_ms")

# From a stored sandbox result envelope we surface only non-sensitive,
# bounded operational facts; stdout, stderr, fingerprint and arguments are
# intentionally omitted.
_SANDBOX_RESULT_KEYS = ("decision", "exit_code", "duration_ms")
_ALLOWED_DECISIONS = frozenset(("ALLOW", "DENY"))

# Stored sandbox error text is arbitrary and may embed a credential, an
# absolute path or a workload argument, so it is never exported.  Instead the
# raw text is matched against coarse patterns and only the resulting category
# (itself from a fixed allowlist) is emitted.
_DIAGNOSTIC_RULES = (
    ("timed out", "TIMEOUT"),
    ("timeout", "TIMEOUT"),
    ("deadline exceeded", "TIMEOUT"),
    ("permission denied", "PERMISSION_DENIED"),
    ("operation not permitted", "PERMISSION_DENIED"),
    ("not permitted", "PERMISSION_DENIED"),
    ("unauthorised", "UNAUTHORISED"),
    ("unauthorized", "UNAUTHORISED"),
    ("invalid permit", "UNAUTHORISED"),
    ("fingerprint", "INTEGRITY_MISMATCH"),
    ("mismatch", "INTEGRITY_MISMATCH"),
    ("no such image", "IMAGE_NOT_FOUND"),
    ("no such file", "PATH_NOT_FOUND"),
    ("not found", "NOT_FOUND"),
    ("out of memory", "RESOURCE_LIMIT"),
    ("memory limit", "RESOURCE_LIMIT"),
    ("cpu limit", "RESOURCE_LIMIT"),
    ("pids limit", "RESOURCE_LIMIT"),
    ("no space left", "RESOURCE_LIMIT"),
    ("killed", "TERMINATED"),
    ("terminated", "TERMINATED"),
    ("signal", "TERMINATED"),
    ("cancel", "CANCELLED"),
    ("connection refused", "BROKER_UNAVAILABLE"),
    ("socket", "BROKER_UNAVAILABLE"),
    ("broker", "BROKER_UNAVAILABLE"),
)
_DIAGNOSTIC_CATEGORIES = frozenset(
    category for _, category in _DIAGNOSTIC_RULES
) | {"UNCLASSIFIED"}

JOB_STATUS_ORDER = (
    "RUNNING", "UNKNOWN", "PENDING", "SUCCEEDED", "DENIED", "CANCELLED",
)
SANDBOX_STATUS_ORDER = (
    "RUNNING", "UNKNOWN", "PENDING", "SUCCEEDED", "FAILED", "DENIED",
    "CANCELLED",
)
_OUTSTANDING = frozenset(("RUNNING", "UNKNOWN"))


class ReportError(ValueError):
    """Invalid input or local state while building the report."""


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _open_readonly(db_path: str | os.PathLike[str]) -> sqlite3.Connection:
    """Open the private SQLite state strictly read-only (never creates it)."""
    path = Path(db_path)
    if not path.is_absolute() or not path.parent.is_dir():
        raise ReportError("Database requires an absolute path and existing parent directory")
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("Private SQLite state requires a POSIX host with O_NOFOLLOW")
    parent = os.stat(path.parent, follow_symlinks=False)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077):
        raise PermissionError("Database parent directory must be owned by this user and private (0700)")
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        raise ReportError("Database file does not exist; generate state before exporting")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise PermissionError("Database must be a regular file, owned by the process, mode 0600")
    uri = "file:" + quote(str(path), safe="/:") + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5, factory=PrivateConnection)
    except sqlite3.Error as exc:
        raise ReportError("Database cannot be opened read-only") from exc
    conn.row_factory = sqlite3.Row
    # Belt-and-braces: reject any accidental write even if a caller mistakes it.
    try:
        conn.execute("PRAGMA query_only=ON")
    except sqlite3.Error as exc:
        conn.close()
        raise ReportError("Database rejected read-only mode") from exc
    return conn


def _optional_rows(
    conn: sqlite3.Connection, table: str, query: str,
) -> list[sqlite3.Row]:
    """Read a table that may be absent in an older state file.

    Only a genuinely absent table yields an empty result.  A present table
    that cannot be read (corruption, a lock timeout or schema drift) is a
    fail-closed error: it must never be reported as healthy-but-empty.
    """
    try:
        present = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise ReportError(f"Cannot inspect schema for optional table {table}") from exc
    if present is None:
        return []
    try:
        return conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        raise ReportError(f"Optional table {table} is present but unreadable") from exc


def _select_allowlisted(row: sqlite3.Row, columns: tuple[str, ...]) -> dict:
    return {column: row[column] for column in columns if column in row.keys()}


def _diagnostic_category(raw: object) -> str | None:
    """Reduce arbitrary stored error text to an allowlisted category."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    lowered = raw.casefold()
    for needle, category in _DIAGNOSTIC_RULES:
        if needle in lowered and category in _DIAGNOSTIC_CATEGORIES:
            return category
    return "UNCLASSIFIED"


def _safe_sandbox_result(raw: object) -> dict | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    safe: dict = {}
    for key in _SANDBOX_RESULT_KEYS:
        value = parsed.get(key)
        if key == "decision":
            if isinstance(value, str) and value in _ALLOWED_DECISIONS:
                safe[key] = value
        elif isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            safe[key] = value
    # The raw error string is intentionally discarded; only the category is kept.
    category = _diagnostic_category(parsed.get("error"))
    if category is not None:
        safe["diagnostic"] = category
    return safe or None


def collect_snapshot(
    db_path: str | os.PathLike[str], *, now_ms: int | None = None,
) -> dict:
    """Gather an allowlisted, non-sensitive snapshot of current local state."""
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise ReportError("Invalid report clock")
    conn: sqlite3.Connection | None = None
    try:
        conn = _open_readonly(db_path)
        control_row = conn.execute(
            "SELECT halted,reason,updated_at_ms FROM control WHERE singleton=1"
        ).fetchone()
        job_rows = _optional_rows(
            conn, "jobs",
            "SELECT job_id,tool,status,run_at_ms,created_at_ms,started_at_ms,"
            "finished_at_ms FROM jobs ORDER BY run_at_ms,job_id",
        )
        sandbox_rows = _optional_rows(
            conn, "sandbox_jobs",
            "SELECT job_id,status,run_at_ms,created_at_ms,started_at_ms,"
            "finished_at_ms,result_json FROM sandbox_jobs ORDER BY run_at_ms,job_id",
        )
        schedule_rows = _optional_rows(
            conn, "recurring_schedules",
            "SELECT schedule_id,name,interval_ms,next_due_ms,window_ms,tool,"
            "enabled,last_job_id,skipped_intervals FROM recurring_schedules "
            "ORDER BY name",
        )
    except sqlite3.Error as exc:
        # Corruption, a lock timeout or a malformed query must surface as a
        # clean error, never as a traceback or a silently empty report.
        raise ReportError("Database state could not be read") from exc
    finally:
        if conn is not None:
            conn.close()

    control = (
        _select_allowlisted(control_row, _CONTROL_COLUMNS)
        if control_row is not None else {"halted": 0, "reason": "", "updated_at_ms": 0}
    )

    jobs = [_select_allowlisted(row, _JOB_COLUMNS) for row in job_rows]
    sandbox_jobs = []
    for row in sandbox_rows:
        job = _select_allowlisted(row, _SANDBOX_COLUMNS)
        job["result"] = _safe_sandbox_result(row["result_json"])
        sandbox_jobs.append(job)
    schedules = [_select_allowlisted(row, _SCHEDULE_COLUMNS) for row in schedule_rows]

    def _counts(items: list[dict], order: tuple[str, ...]) -> dict:
        counts = {status: 0 for status in order}
        for item in items:
            status = item.get("status")
            if isinstance(status, str):
                counts[status] = counts.get(status, 0) + 1
        return counts

    job_counts = _counts(jobs, JOB_STATUS_ORDER)
    sandbox_counts = _counts(sandbox_jobs, SANDBOX_STATUS_ORDER)

    return {
        "generated_at_ms": now,
        "version": __version__,
        "control": {
            "halted": bool(control.get("halted")),
            "reason": control.get("reason") if isinstance(control.get("reason"), str) else "",
            "updated_at_ms": _as_int(control.get("updated_at_ms")) or 0,
        },
        "jobs": jobs,
        "job_counts": job_counts,
        "sandbox_jobs": sandbox_jobs,
        "sandbox_counts": sandbox_counts,
        "schedules": schedules,
    }


# --- Rendering --------------------------------------------------------------

_CSS = """
:root{
  --bg:#eef1f5; --panel:#ffffff; --panel-2:#f5f7fa; --text:#0f141a;
  --muted:#5a6674; --border:#d7dde5; --accent:#2563eb; --accent-weak:#e3ecff;
  --ok:#15803d; --ok-weak:#dcfce7; --warn:#a15c07; --warn-weak:#fef3c7;
  --danger:#b91c1c; --danger-weak:#fee2e2; --unknown:#6d28d9; --unknown-weak:#ede9fe;
  --shadow:0 1px 2px rgba(15,20,26,.08),0 2px 8px rgba(15,20,26,.06);
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0a0e13; --panel:#121922; --panel-2:#0f151d; --text:#e9eef4;
    --muted:#9aa7b5; --border:#243141; --accent:#6aa4ff; --accent-weak:#16243d;
    --ok:#4ade80; --ok-weak:#10291b; --warn:#f5c451; --warn-weak:#2c2310;
    --danger:#f87171; --danger-weak:#2e1416; --unknown:#c4b5fd; --unknown-weak:#241a44;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 2px 10px rgba(0,0,0,.35);
  }
}
html[data-theme="light"]{
  --bg:#eef1f5; --panel:#ffffff; --panel-2:#f5f7fa; --text:#0f141a;
  --muted:#5a6674; --border:#d7dde5; --accent:#2563eb; --accent-weak:#e3ecff;
  --ok:#15803d; --ok-weak:#dcfce7; --warn:#a15c07; --warn-weak:#fef3c7;
  --danger:#b91c1c; --danger-weak:#fee2e2; --unknown:#6d28d9; --unknown-weak:#ede9fe;
  --shadow:0 1px 2px rgba(15,20,26,.08),0 2px 8px rgba(15,20,26,.06);
}
html[data-theme="dark"]{
  --bg:#0a0e13; --panel:#121922; --panel-2:#0f151d; --text:#e9eef4;
  --muted:#9aa7b5; --border:#243141; --accent:#6aa4ff; --accent-weak:#16243d;
  --ok:#4ade80; --ok-weak:#10291b; --warn:#f5c451; --warn-weak:#2c2310;
  --danger:#f87171; --danger-weak:#2e1416; --unknown:#c4b5fd; --unknown-weak:#241a44;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 2px 10px rgba(0,0,0,.35);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0;background:var(--bg);color:var(--text);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,Cantarell,"Helvetica Neue",Arial,sans-serif;
  font-size:16px;line-height:1.5;
  padding:0 0 env(safe-area-inset-bottom,0);
}
.topbar{
  position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;
  gap:12px;padding:12px 16px;padding-top:calc(12px + env(safe-area-inset-top,0));
  background:var(--panel);border-bottom:1px solid var(--border);box-shadow:var(--shadow);
}
.brand{display:flex;flex-direction:column;min-width:0}
.brand b{font-size:1rem;letter-spacing:.01em}
.brand span{font-size:.72rem;color:var(--muted)}
button{
  font:inherit;font-size:.85rem;color:var(--text);background:var(--panel-2);
  border:1px solid var(--border);border-radius:10px;padding:10px 14px;cursor:pointer;
  min-height:44px;
}
button:active{transform:translateY(1px)}
main{max-width:960px;margin:0 auto;padding:16px;display:flex;flex-direction:column;gap:16px}
.card{
  background:var(--panel);border:1px solid var(--border);border-radius:14px;
  padding:16px;box-shadow:var(--shadow);
}
.card h2{margin:0 0 12px;font-size:1rem;letter-spacing:.01em}
.card h2 small{display:block;font-size:.72rem;font-weight:400;color:var(--muted);margin-top:2px}
.notice{
  border-radius:12px;padding:12px 14px;border:1px solid var(--border);
  background:var(--panel-2);font-size:.85rem;
}
.notice strong{display:block;margin-bottom:2px}
.notice.info{border-color:var(--accent);background:var(--accent-weak)}
.notice.warn{border-color:var(--warn);background:var(--warn-weak)}
.notice.danger{border-color:var(--danger);background:var(--danger-weak)}
.notice.ok{border-color:var(--ok);background:var(--ok-weak)}
.stack{display:flex;flex-direction:column;gap:10px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
@media (min-width:560px){.grid{grid-template-columns:repeat(4,minmax(0,1fr))}}
.stat{
  background:var(--panel-2);border:1px solid var(--border);border-radius:12px;padding:12px;
}
.stat .n{font-size:1.5rem;font-weight:700;line-height:1.1}
.stat .l{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.kv{display:flex;flex-wrap:wrap;gap:8px 20px;font-size:.85rem}
.kv div{min-width:160px}
.kv .k{display:block;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:10px;border:1px solid var(--border)}
table{border-collapse:collapse;width:100%;font-size:.82rem}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--border);white-space:nowrap}
th{background:var(--panel-2);color:var(--muted);font-weight:600;font-size:.72rem;
  text-transform:uppercase;letter-spacing:.05em;position:sticky;top:0}
tbody tr:last-child td{border-bottom:none}
tr.danger td{background:var(--danger-weak)}
tr.warn td{background:var(--warn-weak)}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:.72rem;font-weight:600;
  border:1px solid transparent;white-space:nowrap}
.p-ok{background:var(--ok-weak);color:var(--ok)}
.p-warn{background:var(--warn-weak);color:var(--warn)}
.p-danger{background:var(--danger-weak);color:var(--danger)}
.p-unknown{background:var(--unknown-weak);color:var(--unknown)}
.p-neutral{background:var(--panel-2);color:var(--muted);border-color:var(--border)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:.78rem}
.empty{color:var(--muted);font-size:.85rem;padding:6px 2px}
footer{color:var(--muted);font-size:.75rem;text-align:center;padding:4px 8px 24px;line-height:1.6}
footer .mono{font-size:.72rem}
"""

_SCRIPT_THEME_RESTORE = """
(function(){
  try{
    var s=localStorage.getItem('shards-report-theme');
    if(s==='dark'||s==='light'){document.documentElement.setAttribute('data-theme',s);}
  }catch(e){}
})();
"""

_SCRIPT_THEME_TOGGLE = """
(function(){
  function wire(){
    var root=document.documentElement,key='shards-report-theme';
    var b=document.getElementById('theme-toggle');
    if(!b){return;}
    b.addEventListener('click',function(){
      var cur=root.getAttribute('data-theme');
      if(cur!=='dark'&&cur!=='light'){
        cur=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';
      }
      var next=cur==='dark'?'light':'dark';
      root.setAttribute('data-theme',next);
      try{localStorage.setItem(key,next);}catch(e){}
    });
  }
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',wire);
  }else{
    wire();
  }
})();
"""

_PILL = {
    "SUCCEEDED": "p-ok",
    "RUNNING": "p-warn",
    "PENDING": "p-neutral",
    "UNKNOWN": "p-unknown",
    "DENIED": "p-danger",
    "FAILED": "p-danger",
    "CANCELLED": "p-neutral",
}


def _fmt_ms(ms: object) -> str:
    value = _as_int(ms)
    if value is None or value <= 0:
        return "—"
    try:
        moment = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return "—"
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_duration(ms: object) -> str:
    value = _as_int(ms)
    if value is None or value < 0:
        return "—"
    seconds, remainder = divmod(value, 1000)
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def _pill(status: object) -> str:
    text = status if isinstance(status, str) else "UNKNOWN"
    cls = _PILL.get(text, "p-neutral")
    return f'<span class="pill {cls}">{_escape(text)}</span>'


def _stat_card(number: object, label: str) -> str:
    return f'<div class="stat"><div class="n">{_escape(number)}</div><div class="l">{_escape(label)}</div></div>'


def _jobs_table(jobs: list[dict], *, sandbox: bool) -> str:
    if not jobs:
        return '<p class="empty">No jobs recorded.</p>'
    head = ("Job ID", "Status", "Tool" if not sandbox else "Kind", "Due", "Started", "Finished")
    rows = []
    for job in jobs:
        status = job.get("status")
        row_class = ""
        if status == "RUNNING":
            row_class = ' class="warn"'
        elif status == "UNKNOWN":
            row_class = ' class="danger"'
        kind = "sandbox" if sandbox else _escape(job.get("tool", ""))
        cells = [
            f'<td class="mono">{_escape(job.get("job_id", ""))}</td>',
            f'<td>{_pill(status)}</td>',
            f'<td>{kind}</td>',
            f'<td>{_escape(_fmt_ms(job.get("run_at_ms")))}</td>',
            f'<td>{_escape(_fmt_ms(job.get("started_at_ms")))}</td>',
            f'<td>{_escape(_fmt_ms(job.get("finished_at_ms")))}</td>',
        ]
        rows.append(f'<tr{row_class}>' + "".join(cells) + "</tr>")
    header = "".join(f"<th>{_escape(col)}</th>" for col in head)
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + header + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _sandbox_outcomes_table(jobs: list[dict]) -> str:
    """Optional extra detail for sandbox jobs that carry a stored outcome."""
    detailed = [job for job in jobs if job.get("result")]
    if not detailed:
        return ""
    rows = []
    for job in detailed:
        result = job["result"]
        decision = result.get("decision", "—")
        exit_code = result.get("exit_code", "—")
        duration = _fmt_duration(result.get("duration_ms"))
        diagnostic = result.get("diagnostic", "—")
        rows.append(
            "<tr>"
            f'<td class="mono">{_escape(job.get("job_id", ""))}</td>'
            f"<td>{_pill(job.get('status'))}</td>"
            f"<td>{_escape(decision)}</td>"
            f"<td>{_escape(exit_code)}</td>"
            f"<td>{_escape(duration)}</td>"
            f'<td class="mono">{_escape(diagnostic)}</td>'
            "</tr>"
        )
    return (
        '<div class="table-wrap" style="margin-top:12px"><table><thead><tr>'
        "<th>Job ID</th><th>Status</th><th>Decision</th><th>Exit</th>"
        "<th>Duration</th><th>Diagnostic</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></div>"
    )


def _schedules_table(schedules: list[dict]) -> str:
    if not schedules:
        return '<p class="empty">No recurring schedule templates recorded.</p>'
    rows = []
    for item in schedules:
        enabled = bool(item.get("enabled"))
        state_cell = (
            f'<span class="pill {"p-ok" if enabled else "p-neutral"}">'
            f'{"enabled" if enabled else "disabled"}</span>'
        )
        rows.append(
            "<tr>"
            f'<td>{_escape(item.get("name", ""))}</td>'
            f"<td>{_escape(item.get('tool', ''))}</td>"
            f'<td>every {_escape(_fmt_duration(item.get("interval_ms")))}</td>'
            f'<td>{_escape(_fmt_ms(item.get("next_due_ms")))}</td>'
            f"<td>{state_cell}</td>"
            f'<td>{_escape(item.get("skipped_intervals", 0))}</td>'
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Name</th><th>Tool</th><th>Interval</th><th>Next Due</th>"
        "<th>State</th><th>Skipped</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></div>"
    )


def render_report(snapshot: dict) -> str:
    """Render an allowlisted snapshot dict into a self-contained HTML document."""
    generated = _fmt_ms(snapshot.get("generated_at_ms"))
    version = _escape(snapshot.get("version", ""))
    control = snapshot.get("control", {})
    halted = bool(control.get("halted"))
    reason = control.get("reason", "")
    job_counts = snapshot.get("job_counts", {})
    sandbox_counts = snapshot.get("sandbox_counts", {})
    jobs = snapshot.get("jobs", [])
    sandbox_jobs = snapshot.get("sandbox_jobs", [])
    schedules = snapshot.get("schedules", [])

    # Outstanding = RUNNING or UNKNOWN, across both queues. Sandbox entries are
    # relabelled so the shared table shows which queue they belong to.
    outstanding_labeled = [
        {**job, "tool": job.get("tool", "")}
        for job in jobs if job.get("status") in _OUTSTANDING
    ]
    outstanding_labeled += [
        {**job, "tool": "sandbox"}
        for job in sandbox_jobs if job.get("status") in _OUTSTANDING
    ]

    notices = [
        '<div class="notice info"><strong>Point-in-time snapshot</strong>'
        f"Generated {_escape(generated)}. This file is a static export, not a "
        "live monitoring service. Re-run "
        "<span class=\"mono\">export-report</span> for current state.</div>"
    ]
    if halted:
        detail = f" Reason: {_escape(reason)}" if reason else ""
        notices.append(
            '<div class="notice danger"><strong>Dispatch is HALTED</strong>'
            "New job claims are blocked. In-flight external work is not "
            "preempted by halt.<span class=\"mono\">" + detail + "</span></div>"
        )
    else:
        notices.append(
            '<div class="notice ok"><strong>Dispatch is active</strong>'
            "No local halt latch is set. Kernel permit verification still "
            "applies to every claim.</div>"
        )
    if outstanding_labeled:
        notices.append(
            '<div class="notice warn"><strong>Operator reconciliation '
            f'required</strong>{len(outstanding_labeled)} job(s) are RUNNING or '
            "UNKNOWN. These are never retried automatically; verify external "
            "effects before resuming.</div>"
        )

    job_stat_cards = "".join(
        _stat_card(job_counts.get(status, 0), status)
        for status in JOB_STATUS_ORDER
    )
    sandbox_stat_cards = "".join(
        _stat_card(sandbox_counts.get(status, 0), status)
        for status in SANDBOX_STATUS_ORDER
    )

    halt_state = "HALTED" if halted else "ACTIVE"
    halt_class = "p-danger" if halted else "p-ok"
    halt_kv = (
        '<div class="kv">'
        f'<div><span class="k">Latch</span><span class="pill {halt_class}">{halt_state}</span></div>'
        f'<div><span class="k">Reason</span>{_escape(reason) if reason else "—"}</div>'
        f'<div><span class="k">Updated</span>{_escape(_fmt_ms(control.get("updated_at_ms")))}</div>'
        "</div>"
    )

    sandbox_kv = (
        '<div class="kv">'
        f'<div><span class="k">Sandbox jobs</span>{_escape(len(sandbox_jobs))}</div>'
        f'<div><span class="k">Outstanding</span>'
        f'{_escape(sum(1 for j in sandbox_jobs if j.get("status") in _OUTSTANDING))}</div>'
        "</div>"
    )

    schedule_kv = (
        '<div class="kv">'
        f'<div><span class="k">Templates</span>{_escape(len(schedules))}</div>'
        f'<div><span class="k">Enabled</span>'
        f'{_escape(sum(1 for s in schedules if s.get("enabled")))}</div>'
        "</div>"
    )

    body = f"""<main>
  <section class="stack" aria-label="Notices">{''.join(notices)}</section>

  <section class="card" aria-label="Halt state">
    <h2>Dispatch control<small>Local halt latch governs new claims only</small></h2>
    {halt_kv}
  </section>

  <section class="card" aria-label="Job summary">
    <h2>MCP job summary<small>Governed echo/add queue</small></h2>
    <div class="grid">{job_stat_cards}</div>
  </section>

  <section class="card" aria-label="Outstanding jobs">
    <h2>Outstanding jobs<small>RUNNING and UNKNOWN require reconciliation</small></h2>
    {_jobs_table(outstanding_labeled, sandbox=False) if outstanding_labeled else '<p class="empty">No RUNNING or UNKNOWN jobs. Nothing requires reconciliation.</p>'}
  </section>

  <section class="card" aria-label="All jobs">
    <h2>All MCP jobs<small>Arguments and permit paths are withheld</small></h2>
    {_jobs_table(jobs, sandbox=False)}
  </section>

  <section class="card" aria-label="Sandbox summary">
    <h2>Sandbox job summary<small>Isolated execution queue</small></h2>
    <div class="grid">{sandbox_stat_cards}</div>
    <div style="margin-top:12px">{sandbox_kv}</div>
    {_sandbox_outcomes_table(sandbox_jobs)}
  </section>

  <section class="card" aria-label="Sandbox jobs">
    <h2>All sandbox jobs<small>Workload arguments and output withheld</small></h2>
    {_jobs_table(sandbox_jobs, sandbox=True)}
  </section>

  <section class="card" aria-label="Schedules">
    <h2>Scheduling<small>Inert templates; each occurrence needs a fresh permit</small></h2>
    <div style="margin-bottom:12px">{schedule_kv}</div>
    {_schedules_table(schedules)}
  </section>
</main>
<footer>
  <div>Shards Agent OS <span class="mono">{version}</span> — read-only operational snapshot</div>
  <div>Permit paths, workload arguments, credentials and raw output are never exported.</div>
  <div class="mono">generated {_escape(generated)}</div>
</footer>"""

    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        '<meta name="color-scheme" content="light dark">\n'
        '<meta name="referrer" content="no-referrer">\n'
        "<title>Shards Agent OS — Operational Snapshot</title>\n"
        f"<style>{_CSS}</style>\n"
        f"<script>{_SCRIPT_THEME_RESTORE}</script>\n"
        "</head>\n<body>\n"
        '<header class="topbar">'
        '<div class="brand"><b>Shards Agent OS</b>'
        f'<span>Operational snapshot · {_escape(generated)}</span></div>'
        '<button id="theme-toggle" type="button" aria-label="Toggle colour theme">Theme</button>'
        "</header>\n"
        + body
        + f"\n<script>{_SCRIPT_THEME_TOGGLE}</script>\n"
        + "</body>\n</html>\n"
    )


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _create_output(path: Path, data: bytes) -> None:
    """Create a brand-new private report file; refuse any existing target.

    ``O_EXCL`` makes the existence check and the creation atomic, so an
    existing report, a symlink, or a hard link to the source database is
    refused *without* truncating anything.  Because the target is guaranteed
    new, a failure can only ever remove this process's own partial file.
    """
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):  # defensive; O_EXCL forbids reuse
            raise ReportError("Output must be a regular file")
        os.fchmod(fd, 0o600)
        _write_all(fd, data)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def _replace_output(db_path: str | os.PathLike[str], path: Path, data: bytes) -> None:
    """Replace an existing report atomically, never the source database.

    Only reachable with an explicit ``overwrite`` request.  The target is
    rejected if it is a symlink, a non-regular file, or the same inode as the
    database (which also covers a hard link to it).  The new content is written
    to a private temporary file and ``os.replace``d into place, so a failure at
    any point leaves the previous file intact.
    """
    try:
        target = os.lstat(path)
    except FileNotFoundError:
        target = None
    if target is not None:
        if stat.S_ISLNK(target.st_mode):
            raise ReportError("Refusing to write through a symbolic link")
        if not stat.S_ISREG(target.st_mode):
            raise ReportError("Output must be a regular file")
        try:
            database = os.stat(db_path)
        except OSError:
            database = None
        if database is not None and (database.st_dev, database.st_ino) == (
                target.st_dev, target.st_ino):
            raise ReportError("Refusing to overwrite the source database")
    fd, temp_name = tempfile.mkstemp(prefix=".shards-report-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temp_name, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _write_output(
    db_path: str | os.PathLike[str], output_path: str | os.PathLike[str],
    document: str, *, overwrite: bool = False,
) -> None:
    """Write the report to a private regular file, refusing unsafe targets."""
    path = Path(output_path)
    if not path.is_absolute() or not path.parent.is_dir():
        raise ReportError("Output requires an absolute path and existing parent directory")
    data = document.encode("utf-8")
    if overwrite:
        _replace_output(db_path, path, data)
    else:
        _create_output(path, data)


def export_report(
    db_path: str | os.PathLike[str], output_path: str | os.PathLike[str],
    *, now_ms: int | None = None, overwrite: bool = False,
) -> dict:
    """Export a self-contained HTML operational snapshot. Read-only, offline.

    By default an existing output path is refused (``O_EXCL``); pass
    ``overwrite=True`` to atomically replace a prior report.  The source
    database is never a valid destination in either mode.
    """
    snapshot = collect_snapshot(db_path, now_ms=now_ms)
    document = render_report(snapshot)
    _write_output(db_path, output_path, document, overwrite=overwrite)
    return {
        "status": "EXPORTED",
        "output": str(Path(output_path)),
        "overwritten": bool(overwrite),
        "generated_at_ms": snapshot["generated_at_ms"],
        "jobs": len(snapshot["jobs"]),
        "sandbox_jobs": len(snapshot["sandbox_jobs"]),
        "schedules": len(snapshot["schedules"]),
        "halted": snapshot["control"]["halted"],
    }
