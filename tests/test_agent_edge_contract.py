"""Cross-language contract: the Worker's assertion must satisfy the origin.

The edge mints an HMAC assertion in JavaScript; the origin verifies it in
Python. If these two ever drift, sign-in silently breaks in production while
both unit suites stay green. This test generates the assertion with *Node*
and verifies it with the *real* Python verifier, so the contract is pinned
from both sides.

Skipped when `node` is unavailable; CI runs it on the standard runners.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import unittest

from shards_agent_os.web_server import WebError, verify_assertion

EDGE_SECRET = b"origin-secret-0123456789abcdefghijklmnop"
WORKER_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "deploy", "cloudflare")

NODE = shutil.which("node")


def mint_with_node(actor: str, nonce: str, ts_ms: int, secret: bytes) -> str:
    script = """
import { mintOriginAssertion } from './worker.mjs';
const [secret, actor, nonce, ts] = process.argv.slice(1);
const signature = await mintOriginAssertion(secret, {
  actor, nonce, tsMs: Number(ts),
});
process.stdout.write(signature);
"""
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", script,
         secret.decode("utf-8"), actor, nonce, str(ts_ms)],
        cwd=WORKER_DIR, capture_output=True, text=True, timeout=60, check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"node failed: {completed.stderr[:400]}")
    return completed.stdout.strip()


@unittest.skipUnless(NODE, "node is required for the cross-language contract test")
class WorkerOriginAssertionContractTests(unittest.TestCase):
    def test_node_signature_is_accepted_by_the_python_origin(self):
        now = int(time.time() * 1000)
        signature = mint_with_node("owner@example.test", "nonce-0123456789abcdef",
                                   now, EDGE_SECRET)
        self.assertRegex(signature, r"^[0-9a-f]{64}$")
        # Must not raise.
        verify_assertion(EDGE_SECRET, actor="owner@example.test",
                         nonce="nonce-0123456789abcdef", ts_ms=now,
                         signature=signature)

    def test_python_rejects_a_node_signature_for_a_different_actor(self):
        now = int(time.time() * 1000)
        signature = mint_with_node("owner@example.test", "nonce-0123456789abcdef",
                                   now, EDGE_SECRET)
        with self.assertRaises(WebError) as caught:
            verify_assertion(EDGE_SECRET, actor="attacker@example.test",
                             nonce="nonce-0123456789abcdef", ts_ms=now,
                             signature=signature)
        self.assertEqual(caught.exception.code, "ASSERTION_INVALID")

    def test_python_rejects_a_node_signature_made_with_another_secret(self):
        now = int(time.time() * 1000)
        signature = mint_with_node("owner@example.test", "nonce-0123456789abcdef",
                                   now, b"a-different-secret-0123456789abcdefgh")
        with self.assertRaises(WebError) as caught:
            verify_assertion(EDGE_SECRET, actor="owner@example.test",
                             nonce="nonce-0123456789abcdef", ts_ms=now,
                             signature=signature)
        self.assertEqual(caught.exception.code, "ASSERTION_INVALID")

    def test_python_rejects_a_stale_node_signature(self):
        old = int(time.time() * 1000) - 900_000
        signature = mint_with_node("owner@example.test", "nonce-0123456789abcdef",
                                   old, EDGE_SECRET)
        with self.assertRaises(WebError) as caught:
            verify_assertion(EDGE_SECRET, actor="owner@example.test",
                             nonce="nonce-0123456789abcdef", ts_ms=old,
                             signature=signature)
        self.assertEqual(caught.exception.code, "ASSERTION_EXPIRED")


if __name__ == "__main__":
    unittest.main()
