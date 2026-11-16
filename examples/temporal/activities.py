"""One bounded, governed read-only Activity. No write tools, no permit signing API."""
from __future__ import annotations

import asyncio
import os

from temporalio import activity

from contracts import require_exact_repository, sanitise_governed_report


def _inspect(repository: str) -> dict:
    configured = os.environ.get("SHARDS_TEMPORAL_REPOSITORY", "")
    require_exact_repository(repository, configured)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("Worker requires a scoped read-only GITHUB_TOKEN")
    # This existing Shards pilot issues an *ephemeral same-process HMAC permit*
    # for one fixed GitHub GET. It is NOT a production independent issuer.
    from shards_github_agent.github_read import GitHubReadClient
    from shards_github_agent.kernel_agent import inspect_once

    handler = GitHubReadClient(repository, token).list_workflow_runs
    report, _evidence = inspect_once(repository, handler)
    return sanitise_governed_report(report, repository)


@activity.defn(name="shards_governed_github_readonly")
async def governed_github_readonly(repository: str) -> dict:
    # Blocking HTTP/kernel operations run outside the event loop.
    return await asyncio.to_thread(_inspect, repository)
