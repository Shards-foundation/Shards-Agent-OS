"""Shards Agent OS CLI."""

from __future__ import annotations

import argparse
import json
import sys
import time

from .scheduler import cancel_pending, enqueue, list_jobs, run_once


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="shards-agent-os")
    p.add_argument("--db", required=True, help="Absolute path to a private SQLite DB")
    commands = p.add_subparsers(dest="command", required=True)
    create = commands.add_parser("enqueue", help="Queue one separately authorised MCP call")
    create.add_argument("--run-at-ms", type=int, default=None)
    create.add_argument("--port", type=int, required=True)
    create.add_argument("--tool", choices=("echo", "add"), required=True)
    create.add_argument("--arguments-json", required=True)
    create.add_argument("--permit-file", required=True)
    run = commands.add_parser("run-once", help="Execute at most one due job")
    run.add_argument("--timeout", type=float, default=30.0)
    commands.add_parser("list", help="Inspect job state without displaying permit paths")
    cancel = commands.add_parser("cancel", help="Cancel a pending job only")
    cancel.add_argument("job_id")
    args = p.parse_args(argv)
    try:
        if args.command == "enqueue":
            payload = json.loads(args.arguments_json)
            job_id = enqueue(
                args.db, run_at_ms=args.run_at_ms if args.run_at_ms is not None else int(time.time() * 1000),
                port=args.port, tool=args.tool, arguments=payload, permit_file=args.permit_file,
            )
            result = {"job_id": job_id, "status": "PENDING"}
        elif args.command == "run-once":
            result = run_once(args.db, timeout_s=args.timeout) or {"status": "NO_DUE_JOB"}
        elif args.command == "cancel":
            if not cancel_pending(args.db, args.job_id):
                print(json.dumps({"status": "NOT_CANCELLED"}))
                return 2
            result = {"job_id": args.job_id, "status": "CANCELLED"}
        else:
            result = {"jobs": list_jobs(args.db)}
    except (ValueError, OSError, PermissionError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "ERROR", "error": type(exc).__name__}))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
