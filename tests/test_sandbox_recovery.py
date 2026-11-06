"""No silent replay, unauthorised deletion, or orphan leakage on restart."""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from shards_agent_os.sandbox_executor import (
    ExecutionSpec, GVisorExecutor, SandboxUnavailable,
)
from shards_agent_os.sandbox_recovery import recover_orphans

LABEL = "shards.agent-os.sandbox"
OWNER = "shards.agent-os.owner"
NAME = "shards-sbx-" + "a" * 32
OWNER_ID = "sandbox-recovery-tests"


def completed(argv, code=0, out="", err=""):
    return subprocess.CompletedProcess(argv, code, out, err)


class OrphanRecoveryUnitTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "audit.sqlite3"
        self.executor = GVisorExecutor(
            docker_binary="/usr/bin/docker", owner_id=OWNER_ID
        )
        self.preflight = patch.object(self.executor, "_preflight", return_value=None)
        self.preflight.start()
        self.addCleanup(self.preflight.stop)

    def test_rejects_unbound_or_different_owner(self):
        for owner in ("other-operator", "", "bad owner"):
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                recover_orphans(self.executor, audit_db=self.db, owner_id=owner)

    def test_owner_is_stamped_into_every_workload(self):
        spec = ExecutionSpec(
            image="busybox@sha256:" + "a" * 64, argv=("/bin/echo", "hi")
        )
        command = self.executor._command(spec, NAME)
        self.assertIn(f"{OWNER}={OWNER_ID}", command)
        self.assertIn(f"{LABEL}=1", command)
        with self.assertRaises(ValueError):
            GVisorExecutor(docker_binary="/usr/bin/docker", owner_id="evil name")

    def test_recover_one_owned_container_then_no_replay(self):
        calls = []
        def run(_executor, args, _env, **kw):
            calls.append(args)
            if args[0:2] == ["container", "ls"]:
                return completed(args, out=NAME + "\n")
            if args[:2] == ["container", "inspect"]:
                # First inspect confirms ownership; after rm it is absent.
                if any(c[:3] == ["container", "rm", "--force"] for c in calls):
                    return completed(args, code=1, err="Error: No such container")
                return completed(args, out='{"%s":"1","%s":"%s"}\n' % (
                    LABEL, OWNER, OWNER_ID,
                ))
            if args[:2] == ["container", "rm"]:
                return completed(args)
            self.fail(f"unexpected Docker call: {args}")
        with patch("shards_agent_os.sandbox_recovery._docker", side_effect=run):
            self.assertEqual(
                recover_orphans(self.executor, audit_db=self.db, owner_id=OWNER_ID),
                [NAME],
            )
        with sqlite3.connect(self.db) as db:
            row = db.execute(
                "SELECT outcome FROM sandbox_orphan_recovery "
                "WHERE container_name=?", (NAME,),
            ).fetchone()
        self.assertEqual(row, ("REMOVED",))

    def test_cross_operator_label_spoof_fails_closed(self):
        events = []
        def run(_executor, args, _env, **kw):
            events.append(args)
            if args[0:2] == ["container", "ls"]:
                return completed(args, out=NAME + "\n")
            if args[0:2] == ["container", "inspect"]:
                return completed(args, out='{"%s":"1","%s":"someone-else"}' % (
                    LABEL, OWNER,
                ))
            self.fail("Must never attempt forced removal for another operator")
        with patch("shards_agent_os.sandbox_recovery._docker", side_effect=run):
            with self.assertRaisesRegex(SandboxUnavailable, "ownership"):
                recover_orphans(self.executor, audit_db=self.db, owner_id=OWNER_ID)
        self.assertFalse(any(x[:2] == ["container", "rm"] for x in events))
        with sqlite3.connect(self.db) as db:
            row = db.execute(
                "SELECT outcome FROM sandbox_orphan_recovery "
                "WHERE container_name=?", (NAME,),
            ).fetchone()
        self.assertEqual(row, ("STARTED",))

    def test_restart_recovers_interrupted_cleanup_journal(self):
        with sqlite3.connect(self.db) as db:
            db.execute(
                "CREATE TABLE sandbox_orphan_recovery "
                "(container_name TEXT PRIMARY KEY, operator_id TEXT NOT NULL, "
                "first_seen_ms INTEGER NOT NULL, completed_ms INTEGER, "
                "outcome TEXT NOT NULL)"
            )
            db.execute(
                "INSERT INTO sandbox_orphan_recovery VALUES (?,?,1,NULL,'STARTED')",
                (NAME, OWNER_ID),
            )
        def run(_executor, args, _env, **kw):
            if args[:2] == ["container", "ls"]:
                return completed(args)
            if args[:2] == ["container", "inspect"]:
                return completed(args, code=1, err="Error: No such container")
            self.fail("An already absent workload must not be relaunched or removed")
        with patch("shards_agent_os.sandbox_recovery._docker", side_effect=run):
            self.assertEqual(
                recover_orphans(self.executor, audit_db=self.db, owner_id=OWNER_ID),
                [NAME],
            )
        with sqlite3.connect(self.db) as db:
            row = db.execute(
                "SELECT outcome FROM sandbox_orphan_recovery "
                "WHERE container_name=?", (NAME,),
            ).fetchone()
        self.assertEqual(row, ("ABSENT",))

    def test_invalid_listing_or_daemon_error_refuses_startup(self):
        for response in (
            completed([], code=1, err="daemon unavailable"),
            completed([], out="unowned-unexpected-container\n"),
            completed([], out="\n".join([NAME] * 129)),
        ):
            with self.subTest(response=response):
                with patch(
                    "shards_agent_os.sandbox_recovery._docker",
                    return_value=response,
                ):
                    with self.assertRaises(SandboxUnavailable):
                        recover_orphans(
                            self.executor, audit_db=self.db, owner_id=OWNER_ID
                        )


@unittest.skipUnless(
    sys.platform.startswith("linux") and os.environ.get("SHARDS_SANDBOX_LIVE") == "1",
    "Ephemeral Linux runner with a real gVisor Docker runtime required",
)
class RealGVisorOrphanRecoveryTests(unittest.TestCase):
    def test_force_reap_only_owned_orphans_and_verify_journal(self):
        image = os.environ.get("SHARDS_SANDBOX_IMAGE", "")
        self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
        owner = "reaper-e2e-owner"
        foreign_owner = "other-e2e-owner"
        target = "shards-sbx-" + uuid.uuid4().hex
        foreign = "shards-sbx-" + uuid.uuid4().hex
        base = ["docker", "--host", "unix:///var/run/docker.sock"]

        def docker(*args, success=True):
            result = subprocess.run(
                base + list(args), capture_output=True, text=True, timeout=25,
                check=False,
            )
            if success and result.returncode:
                self.fail(
                    "Docker operation failed: " + " ".join(args[:3]) +
                    ": " + result.stderr[:250]
                )
            return result

        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "audit.sqlite3"
            # This is a trusted test fixture simulating the original process
            # crashing after container creation and before Docker cleanup.
            try:
                for name, identity in ((target, owner), (foreign, foreign_owner)):
                    docker(
                        "run", "-d", "--runtime=runsc", "--pull=never",
                        "--network=none", "--read-only", "--cap-drop=ALL",
                        "--label", f"{LABEL}=1",
                        "--label", f"{OWNER}={identity}",
                        "--name", name, image, "/bin/sleep", "60",
                    )
                runner = GVisorExecutor(owner_id=owner)
                reaped = recover_orphans(
                    runner, audit_db=path, owner_id=owner
                )
                self.assertEqual(reaped, [target])
                self.assertNotEqual(
                    docker("container", "inspect", target, success=False).returncode, 0
                )
                self.assertEqual(
                    docker("container", "inspect", foreign).returncode, 0
                )
                self.assertEqual(
                    recover_orphans(runner, audit_db=path, owner_id=owner), []
                )
                with sqlite3.connect(path) as db:
                    row = db.execute(
                        "SELECT outcome FROM sandbox_orphan_recovery "
                        "WHERE container_name=?", (target,),
                    ).fetchone()
                self.assertEqual(row, ("REMOVED",))
            finally:
                docker("container", "rm", "-f", target, success=False)
                docker("container", "rm", "-f", foreign, success=False)


if __name__ == "__main__":
    unittest.main()
