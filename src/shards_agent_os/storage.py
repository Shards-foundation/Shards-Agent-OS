"""Private, local SQLite state. Not an independently anchored audit ledger."""
from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path


class PrivateConnection(sqlite3.Connection):
    """Transaction context that also closes its file handle on exit."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def open_db(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.is_absolute() or not path.parent.is_dir():
        raise ValueError("Database requires an absolute path and existing parent directory")
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("Private SQLite state requires a POSIX host with O_NOFOLLOW")
    # SQLite creates auxiliary -wal/-shm files in this directory. Protect the
    # containing directory as rigorously as the database itself.
    parent = os.stat(path.parent, follow_symlinks=False)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077):
        raise PermissionError("Database parent directory must be owned by this user and private (0700)")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o077) or info.st_uid != os.geteuid():
            raise PermissionError("Database must be a regular file, owned by the process, mode 0600")
        connection = sqlite3.connect(str(path), timeout=5, factory=PrivateConnection)
        try:
            current = os.stat(path, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise PermissionError("Database path replaced during open")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("""CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY, run_at_ms INTEGER NOT NULL,
                port INTEGER NOT NULL, tool TEXT NOT NULL,
                arguments_json TEXT NOT NULL, permit_file TEXT NOT NULL,
                status TEXT NOT NULL, result_json TEXT,
                created_at_ms INTEGER NOT NULL, started_at_ms INTEGER,
                finished_at_ms INTEGER)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS control (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                halted INTEGER NOT NULL CHECK (halted IN (0,1)),
                reason TEXT NOT NULL, updated_at_ms INTEGER NOT NULL)""")
            connection.execute("INSERT OR IGNORE INTO control VALUES (1,0,'',0)")
            connection.execute("""CREATE TABLE IF NOT EXISTS recurring_schedules (
                schedule_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                interval_ms INTEGER NOT NULL CHECK(interval_ms >= 60000),
                next_due_ms INTEGER NOT NULL CHECK(next_due_ms >= 0),
                window_ms INTEGER NOT NULL CHECK(window_ms >= 1000),
                port INTEGER NOT NULL, tool TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                last_issued_at_ms INTEGER, last_job_id TEXT,
                skipped_intervals INTEGER NOT NULL DEFAULT 0)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS schedule_clock (
                singleton INTEGER PRIMARY KEY CHECK (singleton=1),
                high_water_ms INTEGER NOT NULL)""")
            connection.execute("INSERT OR IGNORE INTO schedule_clock VALUES (1,0)")
            connection.execute("""CREATE TABLE IF NOT EXISTS memory (
                namespace TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
                value_json TEXT NOT NULL, provenance TEXT NOT NULL,
                version INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER,
                PRIMARY KEY(namespace,kind,key))""")
            connection.execute("""CREATE TABLE IF NOT EXISTS capabilities (
                capability_id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                description TEXT NOT NULL, allowed_tools TEXT NOT NULL,
                enabled INTEGER NOT NULL CHECK (enabled IN (0,1)))""")
            connection.execute("""CREATE TABLE IF NOT EXISTS agent_directory (
                actor TEXT PRIMARY KEY, description TEXT NOT NULL,
                allowed_tools TEXT NOT NULL, enabled INTEGER NOT NULL CHECK (enabled IN (0,1)))""")
            connection.commit()
            return connection
        except BaseException:
            connection.close()
            raise
    finally:
        os.close(fd)
