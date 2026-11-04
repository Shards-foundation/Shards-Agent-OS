"""Local operator-managed typed memories; no embeddings or model recall claims.

A namespace is a partition identifier, not an authentication mechanism. Do not
expose this module to untrusted agents or through an unauthenticated server.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from .storage import open_db

KINDS = frozenset({'working', 'episodic', 'semantic', 'procedural'})
_ID = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z')


def _validate(namespace: str, kind: str, key: str) -> None:
    if not all(type(s) is str and _ID.fullmatch(s) for s in (namespace, key)):
        raise ValueError('Namespace/key must be 1..64 safe characters')
    if kind not in KINDS:
        raise ValueError('Unrecognised memory kind')


def store(
    db_path: str | Path, *, namespace: str, kind: str, key: str,
    value: Any, provenance: str, ttl_ms: int | None = None,
    expected_version: int | None = None, now_ms: int | None = None,
) -> dict:
    """Set a typed key with an optional optimistic-lock version.

    expected_version=0 means create-only; version N updates exactly version N.
    """
    _validate(namespace, kind, key)
    if type(provenance) is not str or not 1 <= len(provenance) <= 512:
        raise ValueError('Required provenance must be 1..512 characters')
    if ttl_ms is not None and (type(ttl_ms) is not int or not 1 <= ttl_ms <= 31_536_000_000):
        raise ValueError('TTL must be 1 ms..365 days')
    if expected_version is not None and (type(expected_version) is not int or expected_version < 0):
        raise ValueError('Invalid expected version')
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 65536:
        raise ValueError('Memory value exceeds 64 KiB')
    now = int(time.time() * 1000) if now_ms is None else now_ms
    expires = now + ttl_ms if ttl_ms is not None else None
    with open_db(db_path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        existing = conn.execute('SELECT version FROM memory WHERE namespace=? AND kind=? AND key=?',
                                (namespace, kind, key)).fetchone()
        previous = existing['version'] if existing else 0
        if expected_version is not None and expected_version != previous:
            raise ValueError('MEMORY_VERSION_CONFLICT')
        version = previous + 1
        conn.execute('''INSERT INTO memory(namespace,kind,key,value_json,provenance,version,updated_at_ms,expires_at_ms)
                        VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(namespace,kind,key) DO UPDATE SET
                        value_json=excluded.value_json, provenance=excluded.provenance,
                        version=excluded.version, updated_at_ms=excluded.updated_at_ms,
                        expires_at_ms=excluded.expires_at_ms''',
                     (namespace, kind, key, encoded, provenance, version, now, expires))
    return {'namespace': namespace, 'kind': kind, 'key': key, 'version': version, 'expires_at_ms': expires}


def recall(db_path: str | Path, *, namespace: str, kind: str, key: str,
           now_ms: int | None = None) -> dict | None:
    _validate(namespace, kind, key)
    now = int(time.time() * 1000) if now_ms is None else now_ms
    with open_db(db_path) as conn:
        row = conn.execute('''SELECT value_json,provenance,version,updated_at_ms,expires_at_ms
                              FROM memory WHERE namespace=? AND kind=? AND key=?''',
                           (namespace,kind,key)).fetchone()
        if row is None or (row['expires_at_ms'] is not None and row['expires_at_ms'] <= now):
            return None
        return {'namespace': namespace, 'kind': kind, 'key': key,
                'value': json.loads(row['value_json']), 'provenance': row['provenance'],
                'version': row['version'], 'updated_at_ms': row['updated_at_ms'],
                'expires_at_ms': row['expires_at_ms']}


def delete(db_path: str | Path, *, namespace: str, kind: str, key: str,
           expected_version: int | None = None) -> bool:
    _validate(namespace, kind, key)
    if expected_version is not None and (type(expected_version) is not int or expected_version <= 0):
        raise ValueError('Invalid expected version')
    with open_db(db_path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        query = 'DELETE FROM memory WHERE namespace=? AND kind=? AND key=?'
        args = (namespace,kind,key)
        if expected_version is not None:
            query += ' AND version=?'
            args += (expected_version,)
        return conn.execute(query,args).rowcount == 1


def purge_expired(db_path: str | Path, now_ms: int | None = None) -> int:
    now = int(time.time()*1000) if now_ms is None else now_ms
    with open_db(db_path) as conn:
        return conn.execute('DELETE FROM memory WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?', (now,)).rowcount
