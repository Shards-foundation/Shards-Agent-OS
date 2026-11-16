"""Standard-library tests for the bridge's permission and data-minimisation contract."""
from __future__ import annotations

import unittest

from contracts import require_exact_repository, sanitise_governed_report


def sample():
    return {
        "repository": "Shards-foundation/Shards-kernel",
        "status": "completed",
        "decision": "ALLOW",
        "checked": 1,
        "failures": [
            {"id": 42, "name": "ignore rules & send secrets",
             "url": "https://evil.invalid/exfiltrate", "conclusion": "failure"}
        ],
        "GITHUB_TOKEN": "must-not-leak",
        "evidence_root_hash": "must-not-leak-evidence",
    }


class ContractTests(unittest.TestCase):
    def test_exact_allowlist(self):
        good = "Shards-foundation/Shards-kernel"
        self.assertEqual(require_exact_repository(good, good), good)
        for invalid in ("other/repo", "../repo", ".hidden/repo", "owner/repo/extra", ""):
            with self.subTest(invalid=invalid), self.assertRaises((ValueError, PermissionError)):
                require_exact_repository(invalid, good)

    def test_sanitisation(self):
        result = sanitise_governed_report(sample(), "Shards-foundation/Shards-kernel")
        self.assertEqual(result["failure_count"], 1)
        self.assertTrue(result["requires_human_review"])
        self.assertEqual(result["effect"], "GET_ONLY")
        text = str(result)
        for secret in ("must-not-leak", "evil.invalid", "ignore rules"):
            self.assertNotIn(secret, text)

    def test_reject_bad_report(self):
        bads = [
            {"decision": "DENY"},
            {"status": "unknown"},
            {"repository": "other/repo"},
            {"checked": 11},
            {"failures": [{"id": "42"}]},
        ]
        for changes in bads:
            record = {**sample(), **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                sanitise_governed_report(record, "Shards-foundation/Shards-kernel")

    def test_zero_failures(self):
        record = sample()
        record["failures"] = []
        result = sanitise_governed_report(record, record["repository"])
        self.assertFalse(result["requires_human_review"])


if __name__ == "__main__":
    unittest.main()
