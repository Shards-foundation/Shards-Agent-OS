"""End-to-end: real signed Shards-Kernel execution driven by the governed loop.

This is the acceptance test that matters most. It starts an actual
``shards_kernel serve`` operator with an ephemeral signed policy, issues a real
single-use Ed25519 permit, attests it with the independent authority, and then
drives the loop with a scripted *transport* so the assertions are about
governance rather than about model quality.

Real Qwen inference is proven separately in ``test_agent_qwen_live.py``; the
combination of the two is the full vertical slice.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shards_agent_os import agent_state
from shards_agent_os.agent_loop import run_turn
from shards_agent_os.tool_permit_authority import arguments_digest

from tests.agent_fixtures import (
    ACTOR, ScriptedProvider, Workspace, decision, issue_add_permit,
    issue_echo_permit, start_signed_kernel,
)

DEPENDENCIES = all(
    importlib.util.find_spec(name) is not None
    for name in ("shards_kernel", "cryptography", "mcp")
)
AGENT_TOKEN = "agent-os-web." + "z" * 64


@unittest.skipUnless(os.name == "posix" and DEPENDENCIES,
                     "POSIX + Shards-Kernel crypto and MCP extras required")
class GovernedKernelExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One real signed operator for the whole class; the policy lives in a
        # private directory that every test can read but none can mutate.
        cls.kernel_root = Path(tempfile.mkdtemp())
        os.chmod(cls.kernel_root, 0o700)
        cls.proc, cls.port, cls.ctx = start_signed_kernel(
            cls.kernel_root,
            agents=[{"actor": "agent-os-web", "token": AGENT_TOKEN,
                     "allowed_tools": ["echo", "add"]}],
            tools=["echo", "add"],
        )

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=8)
        except Exception:
            cls.proc.kill()
            cls.proc.wait(timeout=8)
        shutil.rmtree(cls.kernel_root, ignore_errors=True)

    def setUp(self):
        # A fresh Agent OS database per test: queue state must not leak between
        # cases, and a stale PENDING job must never be claimed by a later test.
        self.ws = Workspace()
        self.conversation = self.ws.conversation()

    def tearDown(self):
        self.ws.close()

    def _turn(self, provider, authority, question="Run the reference tool."):
        with patch.dict(os.environ, {"SHARDS_KERNEL_AGENT_TOKEN": AGENT_TOKEN}):
            return run_turn(
                self.ws.db_path, actor=ACTOR, conversation_id=self.conversation,
                question=question, provider=provider, authority=authority,
                kernel_port=self.port,
            )

    def test_real_signed_kernel_echo_allows_once(self):
        permit = issue_echo_permit(self.ws.root, self.ctx, text="governed-hello",
                                   subject="agent-os-web")
        authority = self.ws.authority(bundles={
            arguments_digest("kernel.echo", {"text": "governed-hello"}):
                self.ws.bundle(tool="kernel.echo",
                               arguments={"text": "governed-hello"},
                               permit_file=permit),
        })
        provider = ScriptedProvider(
            decision("Running the reference echo tool.", "kernel.echo",
                     {"text": "governed-hello"})
        )
        turn = self._turn(provider, authority)
        self.assertEqual(turn["status"], "SUCCEEDED", turn)
        self.assertEqual(turn["tool_status"], "SUCCEEDED")
        self.assertEqual(turn["tool_name"], "kernel.echo")
        self.assertIsNotNone(turn["job_id"])
        result_receipt = [r for r in turn["receipts"] if r["kind"] == "tool.result"][0]
        self.assertEqual(result_receipt["payload"]["decision"], "ALLOW")
        self.assertEqual(result_receipt["payload"]["result"], "governed-hello")
        self.assertIn("governed-hello", turn["reply"])

    def test_real_signed_kernel_add_claims_its_own_job(self):
        from shards_agent_os.scheduler import enqueue, list_jobs

        older = enqueue(
            self.ws.db_path, run_at_ms=1, now_ms=1, port=self.port, tool="echo",
            arguments={"text": "older"}, permit_file=str(self.ws.root / "other-permit.json"),
        )
        permit = issue_add_permit(self.ws.root, self.ctx, a=17, b=25,
                                  subject="agent-os-web")
        arguments = {"a": 17, "b": 25}
        authority = self.ws.authority(bundles={
            arguments_digest("kernel.add", arguments):
                self.ws.bundle(tool="kernel.add", arguments=arguments,
                               permit_file=permit),
        })
        provider = ScriptedProvider(decision("Adding.", "kernel.add", arguments))
        turn = self._turn(provider, authority)
        jobs = {job["job_id"]: job["status"] for job in list_jobs(self.ws.db_path)}
        self.assertEqual(jobs[older], "PENDING")
        self.assertEqual(jobs[turn["job_id"]], "SUCCEEDED")
        self.assertEqual(turn["status"], "SUCCEEDED", turn)
        self.assertEqual(
            [r for r in turn["receipts"] if r["kind"] == "tool.result"][0]
            ["payload"]["result"],
            42,
        )

    def test_kernel_permit_replay_is_denied_by_the_kernel(self):
        """One signed permit, two attempts: the kernel itself refuses the second."""
        permit = issue_echo_permit(self.ws.root, self.ctx, text="replay-me",
                                   subject="agent-os-web")
        bundle = self.ws.bundle(tool="kernel.echo", arguments={"text": "replay-me"},
                                permit_file=permit)
        authority = self.ws.authority(bundles={
            arguments_digest("kernel.echo", {"text": "replay-me"}): bundle,
        })
        provider = ScriptedProvider(
            decision("first", "kernel.echo", {"text": "replay-me"}),
            decision("second", "kernel.echo", {"text": "replay-me"}),
        )
        first = self._turn(provider, authority)
        self.assertEqual(first["status"], "SUCCEEDED", first)
        # A second bundle for the same exact call must be newly signed by the
        # authority; reusing the file is refused by the one-use grant ledger.
        second = self._turn(provider, authority)
        self.assertEqual(second["status"], "DENIED", second)
        self.assertEqual(second["error_code"], "GRANT_ALREADY_USED")

    def test_authority_resigns_but_the_kernel_still_refuses_replay(self):
        """Even with a fresh authority bundle, the kernel's nonce is consumed."""
        permit = issue_echo_permit(self.ws.root, self.ctx, text="nonce-test",
                                   subject="agent-os-web")
        arguments = {"text": "nonce-test"}
        digest = arguments_digest("kernel.echo", arguments)
        first_bundle = self.ws.bundle(tool="kernel.echo", arguments=arguments,
                                      permit_file=permit)
        provider = ScriptedProvider(decision("first", "kernel.echo", arguments))
        first = self._turn(provider, self.ws.authority(bundles={digest: first_bundle}))
        self.assertEqual(first["status"], "SUCCEEDED", first)

        # A second, separately signed bundle pointing at the same permit file.
        second_bundle = os.path.join(str(self.ws.root), "second-bundle.json")
        from shards_agent_os.tool_permit_authority import issue_kernel_bundle

        issue_kernel_bundle(
            private_key_path=self.ws.authority_private, passphrase=self.ws.passphrase,
            output_path=second_bundle, permit_file=permit, audience=self.ws.audience,
            actor=ACTOR, tool="kernel.echo", arguments=arguments, ttl_seconds=600,
        )
        second = self._turn(provider, self.ws.authority(bundles={digest: second_bundle}))
        self.assertEqual(second["status"], "DENIED", second)
        self.assertEqual(second["error_code"], "KERNEL_DENIED")
        self.assertEqual(
            [r for r in second["receipts"] if r["kind"] == "tool.result"][0]
            ["payload"]["decision"],
            "DENY",
        )

    def test_bundle_for_a_different_call_does_not_authorise_this_one(self):
        permit = issue_echo_permit(self.ws.root, self.ctx, text="approved-text",
                                   subject="agent-os-web")
        authority = self.ws.authority(bundles={
            arguments_digest("kernel.echo", {"text": "approved-text"}):
                self.ws.bundle(tool="kernel.echo",
                               arguments={"text": "approved-text"},
                               permit_file=permit),
        })
        provider = ScriptedProvider(
            decision("trying something else", "kernel.echo", {"text": "unapproved"})
        )
        turn = self._turn(provider, authority)
        self.assertEqual(turn["status"], "DENIED")
        self.assertEqual(turn["error_code"], "NO_KERNEL_BUNDLE_FOR_EXACT_CALL")

    def test_tool_result_survives_a_restart_of_the_reader(self):
        """The receipt is durable: a new process reads the same evidence."""
        permit = issue_echo_permit(self.ws.root, self.ctx, text="durable",
                                   subject="agent-os-web")
        authority = self.ws.authority(bundles={
            arguments_digest("kernel.echo", {"text": "durable"}):
                self.ws.bundle(tool="kernel.echo", arguments={"text": "durable"},
                               permit_file=permit),
        })
        provider = ScriptedProvider(decision("ok", "kernel.echo", {"text": "durable"}))
        turn = self._turn(provider, authority)
        self.assertEqual(turn["status"], "SUCCEEDED")
        # Re-open the database from scratch, as a restarted process would.
        reread = agent_state.get_turn(self.ws.db_path, turn_id=turn["turn_id"],
                                      actor=ACTOR)
        self.assertEqual(reread["status"], "SUCCEEDED")
        self.assertEqual(reread["job_id"], turn["job_id"])
        payloads = [r["payload"] for r in reread["receipts"]]
        self.assertTrue(any(p.get("decision") == "ALLOW" for p in payloads))

    def test_unknown_kernel_job_is_visible_for_operator_reconciliation(self):
        from shards_agent_os.recovery_report import build_recovery_report

        permit = issue_echo_permit(self.ws.root, self.ctx, text="crashy",
                                   subject="agent-os-web")
        authority = self.ws.authority(bundles={
            arguments_digest("kernel.echo", {"text": "crashy"}):
                self.ws.bundle(tool="kernel.echo", arguments={"text": "crashy"},
                               permit_file=permit),
        })
        provider = ScriptedProvider(decision("ok", "kernel.echo", {"text": "crashy"}))
        with patch("shards_agent_os.scheduler.run_once",
                   side_effect=RuntimeError("worker died after claim")):
            turn = self._turn(provider, authority)
        self.assertEqual(turn["status"], "UNKNOWN")
        self.assertEqual(turn["error_code"], "TOOL_OUTCOME_UNKNOWN")
        report = build_recovery_report(self.ws.db_path, turn["job_id"])
        self.assertTrue(report["found"])
        self.assertFalse(report["external_effects_verified"])
        # The job is visible and unresolved: no silent success, no replay.
        self.assertIn(report["durable_state"], {"PENDING", "RUNNING", "UNKNOWN"})
        encoded = json.dumps(report)
        # No permit path, no permit material and no workload argument leaks.
        self.assertNotIn("permit.json", encoded)
        self.assertNotIn(str(self.ws.root), encoded)
        self.assertNotIn("crashy", encoded)

    def test_claimed_then_crashed_job_requires_operator_reconciliation(self):
        from shards_agent_os.recovery_report import build_recovery_report
        from shards_agent_os.scheduler import enqueue

        permit = issue_echo_permit(self.ws.root, self.ctx, text="claimed",
                                   subject="agent-os-web")
        now = int(__import__("time").time() * 1000)
        job_id = enqueue(
            self.ws.db_path, run_at_ms=now, port=self.port, tool="echo",
            arguments={"text": "claimed"}, permit_file=permit, now_ms=now,
        )
        # Simulate the worker dying after its atomic claim but before the call.
        with agent_state._connect(self.ws.db_path) as conn:  # noqa: SLF001
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE jobs SET status='RUNNING' WHERE job_id=?", (job_id,))
        report = build_recovery_report(self.ws.db_path, job_id)
        self.assertEqual(report["durable_state"], "RUNNING")
        self.assertTrue(report["manual_reconciliation_required"])
        self.assertEqual(report["completion"], "UNRESOLVED")
        # A stuck claim must never be silently retried.
        self.assertFalse(report["external_effects_verified"])


if __name__ == "__main__":
    unittest.main()
