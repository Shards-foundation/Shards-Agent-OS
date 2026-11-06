"""Local operator CLI for the Shards Agent OS runtime."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .daemon import serve
from .directory import enroll_agent, inventory, register_capability
from .interrupts import control_state, halt, resume
from .memory import delete, purge_expired, recall, store
from .recurrence import (create_schedule, list_schedules, due_schedules,
                         release_occurrence, set_schedule_enabled, skip_missed)
from .scheduler import cancel_pending, enqueue, list_jobs, run_once, reconcile_unknown
from .sandbox_client import _private_json
from .sandbox_jobs import (
    enqueue_sandbox, run_sandbox_once, list_sandbox_jobs,
    cancel_sandbox_pending, reconcile_sandbox_unknown, serve_sandbox,
)
from .storage import open_db


def _strict_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _strict_json(raw: str):
    def refuse_constant(_):
        raise ValueError('Non-finite JSON constant')
    return json.loads(raw, object_pairs_hook=_strict_object, parse_constant=refuse_constant)


def _add_mem_fields(cmd: argparse.ArgumentParser) -> None:
    cmd.add_argument('--namespace', required=True)
    cmd.add_argument('--kind', choices=('working','episodic','semantic','procedural'), required=True)
    cmd.add_argument('--key', required=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog='shards-agent-os')
    p.add_argument('--db', required=True, help='Absolute path to a local private SQLite DB')
    commands = p.add_subparsers(dest='command', required=True)
    create = commands.add_parser('enqueue', help='Queue an independently authorised MCP call')
    create.add_argument('--run-at-ms', type=int, default=None)
    create.add_argument('--port', type=int, required=True)
    create.add_argument('--tool', choices=('echo', 'add'), required=True)
    create.add_argument('--arguments-json', required=True)
    create.add_argument('--permit-file', required=True)
    run = commands.add_parser('run-once', help='Claim at most one due job')
    run.add_argument('--timeout', type=float, default=30.0)
    run.add_argument('--max-running', type=int, default=1)
    daemon = commands.add_parser('serve', help='Poll for scheduled jobs until halt or signal')
    daemon.add_argument('--timeout', type=float, default=30.0)
    daemon.add_argument('--poll', type=float, default=1.0)
    daemon.add_argument('--max-running', type=int, default=1)
    sandbox_enqueue = commands.add_parser(
        'sandbox-enqueue', help='Queue independently approved sandbox.exec for a protected Unix broker',
    )
    sandbox_enqueue.add_argument('--run-at-ms', type=int)
    sandbox_enqueue.add_argument('--operator-uid', type=int, required=True)
    sandbox_enqueue.add_argument('--arguments-file', required=True)
    sandbox_enqueue.add_argument('--permit-file', required=True)
    sandbox_enqueue.add_argument('--socket', default='/run/shards-sandbox/broker.sock')
    sandbox_run = commands.add_parser(
        'sandbox-run-once', help='Claim at most one signed sandbox job; never auto-retry',
    )
    sandbox_run.add_argument('--timeout', type=float, default=150.0)
    sandbox_run.add_argument('--max-running', type=int, default=1)
    sandbox_serve = commands.add_parser(
        'sandbox-serve', help='Poll the separate durable sandbox queue',
    )
    sandbox_serve.add_argument('--timeout', type=float, default=150.0)
    sandbox_serve.add_argument('--poll', type=float, default=1.0)
    sandbox_serve.add_argument('--max-running', type=int, default=1)
    commands.add_parser('sandbox-list', help='List sandbox jobs without permit paths')
    sandbox_cancel = commands.add_parser('sandbox-cancel', help='Cancel a pending sandbox job')
    sandbox_cancel.add_argument('job_id')
    sandbox_reconcile = commands.add_parser(
        'sandbox-reconcile-unknown', help='Classify an investigated stuck sandbox claim as UNKNOWN',
    )
    sandbox_reconcile.add_argument('job_id')
    sandbox_reconcile.add_argument('--incident-id', required=True)
    commands.add_parser('list', help='List jobs without displaying permit file paths')
    commands.add_parser('status', help='Summarise control and queue state')
    cancel = commands.add_parser('cancel', help='Cancel pending only')
    cancel.add_argument('job_id')
    emergency = commands.add_parser('halt', help='Block new claims, not already running work')
    emergency.add_argument('--reason', required=True)
    commands.add_parser('resume', help='Resume local dispatch after operator review')
    reconcile = commands.add_parser('reconcile-unknown', help='Explicitly classify stuck RUNNING as UNKNOWN')
    reconcile.add_argument('job_id')
    reconcile.add_argument('--incident-id', required=True)
    write = commands.add_parser('memory-put', help='Operator-only typed memory upsert')
    _add_mem_fields(write)
    write.add_argument('--value-json', required=True)
    write.add_argument('--provenance', required=True)
    write.add_argument('--ttl-ms', type=int)
    write.add_argument('--expected-version', type=int)
    read = commands.add_parser('memory-get', help='Operator-only memory read')
    _add_mem_fields(read)
    delete_cmd = commands.add_parser('memory-delete', help='Operator-only memory removal')
    _add_mem_fields(delete_cmd)
    delete_cmd.add_argument('--expected-version', type=int)
    commands.add_parser('memory-purge-expired', help='Purge expired memory records')
    agent = commands.add_parser('agent-enroll', help='Register local metadata only (not kernel auth)')
    agent.add_argument('--actor', required=True)
    agent.add_argument('--description', default='')
    agent.add_argument('--tools', default='', help='Comma-separated echo/add subset')
    cap = commands.add_parser('capability-register', help='Inventory only; no device execution')
    cap.add_argument('--id', required=True)
    cap.add_argument('--kind', required=True)
    cap.add_argument('--description', default='')
    cap.add_argument('--tools', default='', help='Comma-separated echo/add subset')
    commands.add_parser('inventory', help='Read local inventories')
    schedule = commands.add_parser('schedule-add', help='Register an inert interval template, no permit')
    schedule.add_argument('--name', required=True)
    schedule.add_argument('--every-ms', type=int, required=True)
    schedule.add_argument('--start-at-ms', type=int)
    schedule.add_argument('--window-ms', type=int, default=60_000)
    schedule.add_argument('--port', type=int, required=True)
    schedule.add_argument('--tool', choices=('echo', 'add'), required=True)
    schedule.add_argument('--arguments-json', required=True)
    commands.add_parser('schedule-list', help='List inert schedule templates')
    commands.add_parser('schedule-due', help='List due templates; never issues permits')
    issue = commands.add_parser('schedule-release', help='Manually bind fresh permit to one occurrence')
    issue.add_argument('schedule_id')
    issue.add_argument('--permit-file', required=True)
    skip = commands.add_parser('schedule-skip', help='Skip expired windows without any permit')
    skip.add_argument('schedule_id')
    for command in ('schedule-enable', 'schedule-disable'):
        toggle = commands.add_parser(command, help='Toggle an inert template')
        toggle.add_argument('schedule_id')
    args = p.parse_args(argv)
    try:
        if args.command == 'enqueue':
            result = {'job_id': enqueue(
                args.db, run_at_ms=args.run_at_ms if args.run_at_ms is not None else int(time.time()*1000),
                port=args.port, tool=args.tool, arguments=_strict_json(args.arguments_json),
                permit_file=args.permit_file), 'status': 'PENDING'}
        elif args.command == 'run-once':
            result = run_once(args.db, timeout_s=args.timeout, max_running=args.max_running)
            if result is None:
                result = {'status': 'HALTED' if control_state(args.db)['halted'] else 'NO_DUE_JOB'}
        elif args.command == 'serve':
            result = {'status': 'STOPPED', 'iterations': serve(args.db, poll_s=args.poll,timeout_s=args.timeout,max_running=args.max_running)}
        elif args.command == 'sandbox-enqueue':
            result = {'job_id': enqueue_sandbox(
                args.db,
                run_at_ms=args.run_at_ms if args.run_at_ms is not None else int(time.time()*1000),
                operator_uid=args.operator_uid,
                arguments=_private_json(args.arguments_file),
                permit_file=args.permit_file, socket_path=args.socket,
            ), 'status': 'PENDING', 'authorised': False}
        elif args.command == 'sandbox-run-once':
            result = run_sandbox_once(
                args.db, timeout_s=args.timeout, max_running=args.max_running,
            )
            if result is None:
                result = {'status': 'HALTED' if control_state(args.db)['halted'] else 'NO_DUE_SANDBOX_JOB'}
        elif args.command == 'sandbox-serve':
            result = {'status': 'STOPPED', 'iterations': serve_sandbox(
                args.db, poll_s=args.poll, timeout_s=args.timeout,
                max_running=args.max_running,
            )}
        elif args.command == 'sandbox-list':
            result = {'jobs': list_sandbox_jobs(args.db)}
        elif args.command == 'sandbox-cancel':
            changed = cancel_sandbox_pending(args.db, args.job_id)
            result = {'job_id': args.job_id, 'status': 'CANCELLED' if changed else 'NOT_CANCELLED'}
            if not changed:
                print(json.dumps(result))
                return 2
        elif args.command == 'sandbox-reconcile-unknown':
            changed = reconcile_sandbox_unknown(
                args.db, job_id=args.job_id, incident_id=args.incident_id,
            )
            result = {'job_id': args.job_id, 'status': 'UNKNOWN', 'reconciled': changed}
            if not changed:
                print(json.dumps(result))
                return 2
        elif args.command == 'list':
            result = {'jobs': list_jobs(args.db)}
        elif args.command == 'status':
            with open_db(args.db) as conn:
                rows = conn.execute('SELECT status,COUNT(*) AS count FROM jobs GROUP BY status').fetchall()
                mem = conn.execute('SELECT COUNT(*) FROM memory').fetchone()[0]
                sandboxes = conn.execute(
                    'SELECT status,COUNT(*) AS count FROM sandbox_jobs GROUP BY status'
                ).fetchall()
            result = {'control': control_state(args.db),
                      'jobs': {r['status']:r['count'] for r in rows},
                      'sandbox_jobs': {r['status']:r['count'] for r in sandboxes},
                      'memory_records':mem}
        elif args.command == 'cancel':
            changed = cancel_pending(args.db,args.job_id)
            result = {'job_id':args.job_id,'status':'CANCELLED' if changed else 'NOT_CANCELLED'}
            if not changed:
                print(json.dumps(result))
                return 2
        elif args.command == 'halt':
            result = {'halted':True,'changed':halt(args.db,args.reason), 'warning':'In-flight kernel work is not preempted'}
        elif args.command == 'resume':
            result = {'halted':False,'changed':resume(args.db)}
        elif args.command == 'reconcile-unknown':
            result = {'job_id':args.job_id,
                      'reconciled':reconcile_unknown(args.db,args.job_id,args.incident_id),
                      'status':'UNKNOWN'}
        elif args.command == 'memory-put':
            result = store(args.db,namespace=args.namespace,kind=args.kind,key=args.key,
                           value=_strict_json(args.value_json),provenance=args.provenance,
                           ttl_ms=args.ttl_ms,expected_version=args.expected_version)
        elif args.command == 'memory-get':
            result = recall(args.db,namespace=args.namespace,kind=args.kind,key=args.key) or {'status':'NOT_FOUND'}
        elif args.command == 'memory-delete':
            result = {'deleted':delete(args.db,namespace=args.namespace,kind=args.kind,key=args.key,
                                       expected_version=args.expected_version)}
        elif args.command == 'memory-purge-expired':
            result = {'purged':purge_expired(args.db)}
        elif args.command == 'agent-enroll':
            enroll_agent(args.db,args.actor,args.description,[t for t in args.tools.split(',') if t]);result={'status':'RECORDED','kernel_authenticated':False}
        elif args.command == 'capability-register':
            register_capability(args.db,args.id,args.kind,args.description,[t for t in args.tools.split(',') if t]);result={'status':'RECORDED','executable':False}
        elif args.command == 'schedule-add':
            result = {'schedule_id': create_schedule(
                args.db, name=args.name, interval_ms=args.every_ms,
                start_at_ms=args.start_at_ms if args.start_at_ms is not None else int(time.time()*1000),
                window_ms=args.window_ms, port=args.port, tool=args.tool,
                arguments=_strict_json(args.arguments_json)), 'status':'SCHEDULED_UNAUTHORISED'}
        elif args.command == 'schedule-list':
            result = {'schedules': list_schedules(args.db)}
        elif args.command == 'schedule-due':
            result = {'due': due_schedules(args.db)}
        elif args.command == 'schedule-release':
            result = release_occurrence(args.db, schedule_id=args.schedule_id,
                                        permit_file=args.permit_file)
        elif args.command == 'schedule-skip':
            result = skip_missed(args.db, args.schedule_id)
        elif args.command in ('schedule-enable', 'schedule-disable'):
            enabled = args.command == 'schedule-enable'
            result = {'schedule_id':args.schedule_id,
                      'changed': set_schedule_enabled(args.db,args.schedule_id,enabled),
                      'enabled':enabled}
        else:
            result = inventory(args.db)
    except (ValueError, OSError, OverflowError, TypeError, json.JSONDecodeError):
        print(json.dumps({'status':'ERROR','error':'Invalid input or local state'}))
        return 2
    print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
