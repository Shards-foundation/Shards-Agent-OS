"""Temporal orchestration only. Deterministic Workflow code; no API calls here."""
from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy


@workflow.defn
class GovernedReadOnlyGitHubWorkflow:
    @workflow.run
    async def run(self, repository: str) -> dict:
        # Retries are acceptable ONLY because this Activity is explicitly read-only.
        # Never reuse this retry policy for kernel-permitted writes or sandbox.exec.
        return await workflow.execute_activity(
            "shards_governed_github_readonly",
            repository,
            start_to_close_timeout=timedelta(seconds=90),
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=2),
        )
