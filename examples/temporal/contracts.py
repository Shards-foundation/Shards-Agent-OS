"""Pure, non-privileged contract for the experimental Temporal bridge.

No Temporal, GitHub or Shards-Kernel dependencies are required to test this module.
"""
from __future__ import annotations

import re
from typing import Any

_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_STATUSES = frozenset({"completed", "in_progress", "queued", "requested", "waiting", "pending", "unknown"})
_CONCLUSIONS = frozenset({"success", "failure", "cancelled", "timed_out", "action_required", "neutral", "skipped", "stale", "startup_failure", "unknown"})


def validate_repository(value: str) -> str:
    """Validate a repository name shape without granting any allowlist authority."""
    if not isinstance(value, str) or not _REPO.fullmatch(value):
        raise ValueError("Invalid repository")
    if any(part in {".", ".."} or part.startswith(".") for part in value.split("/")):
        raise ValueError("Unsafe repository")
    return value


def require_exact_repository(requested: str, configured: str) -> str:
    """Reject cross-repository requests; configuration is an allowlist of one."""
    if not isinstance(requested, str) or not isinstance(configured, str):
        raise ValueError("Repository must be a string")
    validate_repository(requested)
    validate_repository(configured)
    if requested != configured:
        raise PermissionError("Repository is not operator-allowlisted")
    return requested


def sanitise_governed_report(report: dict[str, Any], repository: str) -> dict[str, Any]:
    """Keep tokens, logs and arbitrary GitHub text out of Temporal Event History."""
    if not isinstance(report, dict):
        raise ValueError("Invalid report")
    if report.get("status") not in _STATUSES:
        raise ValueError("Unrecognised report status")
    if report.get("repository") != repository or report.get("status") != "completed":
        raise ValueError("Unverified or mismatched report")
    if report.get("decision") != "ALLOW":
        raise ValueError("Read not permitted")
    count = report.get("checked")
    if type(count) is not int or count < 0 or count > 10:
        raise ValueError("Invalid bounded run count")
    failures = report.get("failures")
    if not isinstance(failures, list) or len(failures) > 10:
        raise ValueError("Invalid failures")
    clean = []
    for item in failures:
        if not isinstance(item, dict) or type(item.get("id")) is not int or item["id"] < 0:
            raise ValueError("Invalid run identifier")
        conclusion = item.get("conclusion")
        if conclusion is not None and conclusion not in _CONCLUSIONS:
            raise ValueError("Unrecognised run conclusion")
        clean.append({
            "id": item["id"],
            "url": f"https://github.com/{repository}/actions/runs/{item['id']}",
        })
    return {
        "schema": "shards-agent-os/temporal-readonly-v1",
        "repository": repository,
        "checked": count,
        "failure_count": len(clean),
        "failures": clean,
        "requires_human_review": bool(clean),
        "effect": "GET_ONLY",
    }
