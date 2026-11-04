"""Operator-managed metadata directories; not authentication or tool execution."""
from __future__ import annotations

import json
import re
from pathlib import Path
from .storage import open_db

_ID = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z')
_SAFE_TOOLS = {'echo', 'add'}
_SAFE_KINDS = {'filesystem', 'browser', 'camera', 'network', 'mcp', 'api'}


def _validate(identifier: str, description: str, allowed_tools: list[str]):
    if type(identifier) is not str or not _ID.fullmatch(identifier):
        raise ValueError('Invalid identifier')
    if type(description) is not str or len(description) > 1024:
        raise ValueError('Invalid description')
    if type(allowed_tools) is not list or any(type(t) is not str or t not in _SAFE_TOOLS for t in allowed_tools):
        raise ValueError('Only current kernel reference tools may be declared')
    if len(set(allowed_tools)) != len(allowed_tools):
        raise ValueError('Duplicate tool')


def enroll_agent(db_path: str | Path, actor: str, description: str, allowed_tools: list[str]) -> None:
    """Register an operator note; signed kernel policy remains authoritative."""
    _validate(actor, description, allowed_tools)
    with open_db(db_path) as conn:
        conn.execute('''INSERT INTO agent_directory VALUES (?,?,?,1)
                        ON CONFLICT(actor) DO UPDATE SET description=excluded.description,
                        allowed_tools=excluded.allowed_tools,enabled=1''',
                     (actor,description,json.dumps(sorted(allowed_tools))))


def register_capability(db_path: str | Path, capability_id: str, kind: str,
                        description: str, allowed_tools: list[str]) -> None:
    """Record discovery metadata ONLY. No device handle or executor is registered."""
    _validate(capability_id, description, allowed_tools)
    if kind not in _SAFE_KINDS:
        raise ValueError('Invalid capability kind')
    with open_db(db_path) as conn:
        conn.execute('''INSERT INTO capabilities VALUES (?,?,?,?,0)
                        ON CONFLICT(capability_id) DO UPDATE SET kind=excluded.kind,
                        description=excluded.description,allowed_tools=excluded.allowed_tools,enabled=0''',
                     (capability_id,kind,description,json.dumps(sorted(allowed_tools))))


def inventory(db_path: str | Path) -> dict:
    with open_db(db_path) as conn:
        agents = conn.execute('SELECT actor,description,allowed_tools,enabled FROM agent_directory ORDER BY actor').fetchall()
        devices = conn.execute('SELECT capability_id,kind,description,allowed_tools,enabled FROM capabilities ORDER BY capability_id').fetchall()
        return {
            'agents': [{**dict(x), 'allowed_tools': json.loads(x['allowed_tools']), 'kernel_authenticated': False} for x in agents],
            'capabilities': [{**dict(x), 'allowed_tools': json.loads(x['allowed_tools']), 'executable': False} for x in devices],
        }
