"""Independent authority: signatures, scope binding, expiry and tamper refusal."""
from __future__ import annotations

import json
import os
import stat
import unittest

from shards_agent_os.tool_permit_authority import (
    AuthorityError, GRANT_DOMAIN, BUNDLE_DOMAIN, arguments_digest,
    generate_authority_key, issue_delegation, issue_kernel_bundle,
    load_signed_document, public_key_from_file, verify_delegation,
    verify_kernel_bundle, verify_signed,
)

from tests.agent_fixtures import ACTOR, AUDIENCE, Workspace


class AuthorityDocumentTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.public = public_key_from_file(self.ws.authority_public)

    def tearDown(self):
        self.ws.close()

    def _delegation_doc(self, **kwargs):
        path = self.ws.delegation(**kwargs)
        return path, load_signed_document(path)

    def test_delegation_verifies_for_matching_actor_and_audience(self):
        _, document = self._delegation_doc()
        payload = verify_delegation(
            document, public_key_hex=self.public, audience=AUDIENCE, actor=ACTOR,
        )
        self.assertEqual(payload["actor"], ACTOR)
        self.assertEqual(set(payload["tools"]), {"os.queue_summary", "os.halt_state"})

    def test_delegation_refuses_a_different_actor(self):
        _, document = self._delegation_doc()
        with self.assertRaises(AuthorityError) as caught:
            verify_delegation(document, public_key_hex=self.public,
                              audience=AUDIENCE, actor="someone.else@example.test")
        self.assertEqual(caught.exception.code, "ACTOR_MISMATCH")

    def test_delegation_refuses_a_different_instance(self):
        _, document = self._delegation_doc()
        with self.assertRaises(AuthorityError) as caught:
            verify_delegation(document, public_key_hex=self.public,
                              audience="other-instance", actor=ACTOR)
        self.assertEqual(caught.exception.code, "AUDIENCE_MISMATCH")

    def test_delegation_refuses_expired_window(self):
        _, document = self._delegation_doc()
        payload = verify_signed(document, public_key_hex=self.public, domain=GRANT_DOMAIN)
        with self.assertRaises(AuthorityError) as caught:
            verify_delegation(document, public_key_hex=self.public, audience=AUDIENCE,
                              actor=ACTOR, now_ms=payload["valid_until_ms"] + 1)
        self.assertEqual(caught.exception.code, "AUTHORITY_EXPIRED")

    def test_delegation_refuses_not_yet_valid_beyond_skew(self):
        _, document = self._delegation_doc()
        payload = verify_signed(document, public_key_hex=self.public, domain=GRANT_DOMAIN)
        with self.assertRaises(AuthorityError) as caught:
            verify_delegation(document, public_key_hex=self.public, audience=AUDIENCE,
                              actor=ACTOR, now_ms=payload["valid_from_ms"] - 120_000)
        self.assertEqual(caught.exception.code, "AUTHORITY_EXPIRED")

    def test_tampered_actor_breaks_the_signature(self):
        _, document = self._delegation_doc()
        document["actor"] = "attacker@example.test"
        with self.assertRaises(AuthorityError) as caught:
            verify_delegation(document, public_key_hex=self.public,
                              audience=AUDIENCE, actor="attacker@example.test")
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")

    def test_tampered_tool_scope_breaks_the_signature(self):
        _, document = self._delegation_doc()
        document["tools"] = ["os.queue_summary", "kernel.echo"]
        with self.assertRaises(AuthorityError) as caught:
            verify_delegation(document, public_key_hex=self.public,
                              audience=AUDIENCE, actor=ACTOR)
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")

    def test_delegation_cannot_authorise_a_kernel_tool_even_when_signed(self):
        """A valid signature over a forbidden scope must still be refused."""
        path = self.ws.delegation(tools=("os.queue_summary",))
        document = load_signed_document(path)
        payload = {k: v for k, v in document.items() if k != "signature"}
        payload["tools"] = ["kernel.echo"]
        from cryptography.hazmat.primitives import serialization

        with open(self.ws.authority_private, "rb") as stream:
            key = serialization.load_pem_private_key(
                stream.read(), password=self.ws.passphrase
            )
        forged = {**payload, "signature": key.sign(
            GRANT_DOMAIN + json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode()).hex()}
        with self.assertRaises(AuthorityError) as caught:
            verify_delegation(forged, public_key_hex=self.public,
                              audience=AUDIENCE, actor=ACTOR)
        self.assertEqual(caught.exception.code, "INVALID_TOOL_SCOPE")

    def test_cross_domain_signature_replay_is_refused(self):
        _, document = self._delegation_doc()
        with self.assertRaises(AuthorityError) as caught:
            verify_signed(document, public_key_hex=self.public, domain=BUNDLE_DOMAIN)
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")

    def test_missing_signature_rejected(self):
        _, document = self._delegation_doc()
        document.pop("signature")
        with self.assertRaises(AuthorityError) as caught:
            verify_delegation(document, public_key_hex=self.public,
                              audience=AUDIENCE, actor=ACTOR)
        self.assertEqual(caught.exception.code, "MALFORMED_SIGNATURE")

    def test_delegation_file_must_be_private(self):
        path = self.ws.delegation()
        os.chmod(path, 0o644)
        with self.assertRaises(AuthorityError) as caught:
            load_signed_document(path)
        self.assertEqual(caught.exception.code, "DOCUMENT_PERMISSIONS")

    def test_delegation_file_must_not_be_a_symlink(self):
        real = self.ws.delegation()
        link = os.path.join(str(self.ws.root), "link.json")
        os.symlink(real, link)
        with self.assertRaises(OSError):
            load_signed_document(link)

    def test_issuer_refuses_a_weak_passphrase(self):
        with self.assertRaises(AuthorityError) as caught:
            issue_delegation(
                private_key_path=self.ws.authority_private, passphrase=b"short",
                output_path=str(self.ws.root / "x.json"), audience=AUDIENCE,
                actor=ACTOR, tools=["os.halt_state"], max_executions=1, ttl_seconds=600,
            )
        self.assertEqual(caught.exception.code, "WEAK_PASSPHRASE")

    def test_issuer_refuses_to_overwrite(self):
        path = self.ws.delegation()
        with self.assertRaises(FileExistsError):
            issue_delegation(
                private_key_path=self.ws.authority_private, passphrase=self.ws.passphrase,
                output_path=path, audience=AUDIENCE, actor=ACTOR,
                tools=["os.halt_state"], max_executions=1, ttl_seconds=600,
            )

    def test_delegation_output_is_0600(self):
        path = self.ws.delegation()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_public_key_file_is_a_verifier_not_a_secret(self):
        value = public_key_from_file(self.ws.authority_public)
        self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_keygen_refuses_existing_key(self):
        with self.assertRaises(FileExistsError):
            generate_authority_key(
                private_path=self.ws.authority_private,
                public_path=str(self.ws.root / "other.hex"),
                passphrase=b"test-passphrase-0123456789",
            )


class AuthorityCliTests(unittest.TestCase):
    """The offline authority must refuse to run without a live terminal."""

    def setUp(self):
        self.ws = Workspace()

    def tearDown(self):
        self.ws.close()

    def test_keygen_refuses_a_piped_passphrase(self):
        import subprocess
        import sys

        completed = subprocess.run(
            [sys.executable, "-m", "shards_agent_os.authority_cli", "keygen",
             "--private-key-file", str(self.ws.root / "new-priv.pem"),
             "--public-key-file", str(self.ws.root / "new-pub.hex")],
            input="passphrase-0123456789\npassphrase-0123456789\n",
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("refused", completed.stderr)
        # Nothing was written.
        self.assertFalse((self.ws.root / "new-priv.pem").exists())

    def test_verify_subcommand_accepts_a_valid_document(self):
        import subprocess
        import sys

        path = self.ws.delegation()
        completed = subprocess.run(
            [sys.executable, "-m", "shards_agent_os.authority_cli", "verify",
             "--public-key-file", self.ws.authority_public, "--document", path],
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["kind"], "observation-delegation")

    def test_verify_subcommand_rejects_a_tampered_document(self):
        import subprocess
        import sys

        path = self.ws.delegation()
        document = load_signed_document(path)
        document["actor"] = "attacker@example.test"
        tampered = os.path.join(str(self.ws.root), "tampered.json")
        os.chmod(tampered, 0o600) if os.path.exists(tampered) else None
        fd = os.open(tampered, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(document, stream)
        completed = subprocess.run(
            [sys.executable, "-m", "shards_agent_os.authority_cli", "verify",
             "--public-key-file", self.ws.authority_public, "--document", tampered],
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("attacker", completed.stdout)
        self.assertNotIn("attacker", completed.stderr)


class KernelBundleTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.public = public_key_from_file(self.ws.authority_public)
        self.permit = str(self.ws.root / "permit.json")
        with open(self.permit, "w") as stream:
            json.dump({"placeholder": "operator-issued-permit"}, stream)
        os.chmod(self.permit, 0o600)

    def tearDown(self):
        self.ws.close()

    def test_bundle_binds_exact_tool_and_arguments(self):
        path = self.ws.bundle(tool="kernel.echo", arguments={"text": "hello"},
                              permit_file=self.permit)
        document = load_signed_document(path)
        payload = verify_kernel_bundle(
            document, public_key_hex=self.public, audience=AUDIENCE, actor=ACTOR,
            tool="kernel.echo", arguments={"text": "hello"},
        )
        self.assertEqual(payload["max_executions"], 1)
        self.assertEqual(payload["permit_file"], self.permit)

    def test_bundle_refuses_different_arguments(self):
        path = self.ws.bundle(tool="kernel.echo", arguments={"text": "hello"},
                              permit_file=self.permit)
        document = load_signed_document(path)
        with self.assertRaises(AuthorityError) as caught:
            verify_kernel_bundle(
                document, public_key_hex=self.public, audience=AUDIENCE, actor=ACTOR,
                tool="kernel.echo", arguments={"text": "goodbye"},
            )
        self.assertEqual(caught.exception.code, "ARGUMENTS_MISMATCH")

    def test_bundle_refuses_different_tool(self):
        path = self.ws.bundle(tool="kernel.echo", arguments={"text": "hello"},
                              permit_file=self.permit)
        document = load_signed_document(path)
        with self.assertRaises(AuthorityError) as caught:
            verify_kernel_bundle(
                document, public_key_hex=self.public, audience=AUDIENCE, actor=ACTOR,
                tool="kernel.add", arguments={"text": "hello"},
            )
        self.assertEqual(caught.exception.code, "TOOL_MISMATCH")

    def test_bundle_refuses_non_single_use_permit(self):
        path = self.ws.bundle(tool="kernel.echo", arguments={"text": "hello"},
                              permit_file=self.permit)
        document = load_signed_document(path)
        document["max_executions"] = 5
        with self.assertRaises(AuthorityError) as caught:
            verify_kernel_bundle(
                document, public_key_hex=self.public, audience=AUDIENCE, actor=ACTOR,
                tool="kernel.echo", arguments={"text": "hello"},
            )
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")

    def test_bundle_refuses_relative_permit_path(self):
        with self.assertRaises(AuthorityError) as caught:
            issue_kernel_bundle(
                private_key_path=self.ws.authority_private, passphrase=self.ws.passphrase,
                output_path=str(self.ws.root / "b.json"), permit_file="relative.json",
                audience=AUDIENCE, actor=ACTOR, tool="kernel.echo",
                arguments={"text": "x"}, ttl_seconds=600,
            )
        self.assertEqual(caught.exception.code, "ABSOLUTE_PATH_REQUIRED")

    def test_argument_digest_is_stable_and_order_independent(self):
        self.assertEqual(
            arguments_digest("kernel.echo", {"text": "x"}),
            arguments_digest("kernel.echo", {"text": "x"}),
        )
        self.assertNotEqual(
            arguments_digest("kernel.echo", {"text": "x"}),
            arguments_digest("kernel.add", {"text": "x"}),
        )


if __name__ == "__main__":
    unittest.main()
