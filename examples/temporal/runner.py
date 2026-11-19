"""Explicit local-only Temporal development driver for a read-only Shards Activity."""
from __future__ import annotations

import argparse
import asyncio
import os
import uuid
from datetime import timedelta

from temporalio.client import (
    Client, Schedule, ScheduleActionStartWorkflow, ScheduleIntervalSpec,
    ScheduleSpec, ScheduleState,
)
from temporalio.worker import Worker

from activities import governed_github_readonly
from contracts import validate_repository
from workflows import GovernedReadOnlyGitHubWorkflow

QUEUE = "shards-governed-readonly"
SCHEDULE_ID = "shards-governed-github-readonly"
_APPROVAL = "I_APPROVE_LOCAL_READ_ONLY_TEMPORAL_SCHEDULE"


async def main() -> None:
    parser = argparse.ArgumentParser(description="Local-only Shards/Temporal integration pilot")
    parser.add_argument("command", choices=("worker", "once", "create-paused-schedule", "unpause"))
    args = parser.parse_args()

    # Temporal Cloud / remotely reachable endpoints require separate TLS,
    # namespace, credentials and host approval; not configured by this pilot.
    address = os.environ.get("SHARDS_TEMPORAL_ADDRESS", "127.0.0.1:7233")
    if address not in {"127.0.0.1:7233", "localhost:7233"}:
        parser.error("This experimental pilot only accepts a local Temporal development server")
    repository = os.environ.get("SHARDS_TEMPORAL_REPOSITORY", "")
    # The operator names the one repository here; the Activity still enforces
    # that the workflow argument matches this same env value, so this driver
    # only has to reject a malformed name, not duplicate the allowlist check.
    validate_repository(repository)
    client = await Client.connect(address)
    if args.command == "worker":
        worker = Worker(
            client, task_queue=QUEUE,
            workflows=[GovernedReadOnlyGitHubWorkflow],
            activities=[governed_github_readonly],
        )
        await worker.run()
    elif args.command == "once":
        result = await client.execute_workflow(
            GovernedReadOnlyGitHubWorkflow.run, repository,
            id=f"shards-readonly-{uuid.uuid4().hex}",
            task_queue=QUEUE,
        )
        print(result)
    elif args.command == "create-paused-schedule":
        # An installed schedule starts PAUSED. No recurring run until an
        # operator explicitly unpauses it with the approval string below.
        await client.create_schedule(
            SCHEDULE_ID,
            Schedule(
                action=ScheduleActionStartWorkflow(
                    GovernedReadOnlyGitHubWorkflow.run,
                    repository,
                    id="shards-governed-github-readonly",
                    task_queue=QUEUE,
                ),
                spec=ScheduleSpec(
                    intervals=[ScheduleIntervalSpec(every=timedelta(hours=6))]
                ),
                state=ScheduleState(
                    paused=True, note="Review-only; enable explicitly after host and billing checks"
                ),
            ),
        )
        print(f"Created PAUSED Temporal schedule {SCHEDULE_ID}")
    else:
        if os.environ.get("SHARDS_TEMPORAL_SCHEDULE_APPROVAL") != _APPROVAL:
            parser.error("Unpause requires explicit SHARDS_TEMPORAL_SCHEDULE_APPROVAL")
        await client.get_schedule_handle(SCHEDULE_ID).unpause()
        print(f"Unpaused read-only schedule {SCHEDULE_ID}")


if __name__ == "__main__":
    asyncio.run(main())
