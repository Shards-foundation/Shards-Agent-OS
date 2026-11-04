"""Optional Shards Agent OS harness CLI. Execute with python -m shards_agent_os.harness_cli."""
from __future__ import annotations

import argparse
import json
import sys

from .harness import create_task, get_task, list_tasks, refresh_task, release_step


def _strict_object(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            raise ValueError("Duplicate JSON key")
        value[k] = v
    return value


def _strict_json(value):
    return json.loads(value, object_pairs_hook=_strict_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shards-agent-harness")
    parser.add_argument("--db", required=True, help="Absolute private Shards Agent OS SQLite path")
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument("--steps-json", required=True)
    sub.add_parser("list")
    show = sub.add_parser("show")
    show.add_argument("task_id")
    refresh = sub.add_parser("refresh")
    refresh.add_argument("task_id")
    release = sub.add_parser("release")
    release.add_argument("task_id")
    release.add_argument("ordinal", type=int)
    release.add_argument("--permit-file", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "create":
            task_id = create_task(args.db, name=args.name, steps=_strict_json(args.steps_json))
            result = get_task(args.db, task_id)
        elif args.action == "list":
            result = {"tasks": list_tasks(args.db)}
        elif args.action == "show":
            result = get_task(args.db, args.task_id)
        elif args.action == "refresh":
            result = refresh_task(args.db, args.task_id)
        else:
            job_id = release_step(args.db, task_id=args.task_id, ordinal=args.ordinal,
                                  permit_file=args.permit_file)
            result = {"job_id": job_id, "state": "QUEUED", "kernel_allowed": False}
    except (ValueError, OSError, TypeError, OverflowError):
        print('{"status":"ERROR","error":"Invalid request or local state"}')
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
