"""Offline staging commissioning with disposable keys and a private audit path."""
import copy
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from deploy.oracle import commission as stage
except ImportError as exc:
    raise unittest.SkipTest("Kernel crypto extra required") from exc


class CommissionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.enterContext(patch.object(stage, "AUDIT", self.root / "audit.db"))
        self.enterContext(patch.object(stage, "CONFIG", self.root))
        self.key = {role: Ed25519PrivateKey.generate() for role in
                    ("agent-authority", "kernel-policy", "kernel-issuer", "kernel-approver")}
        for role, key in self.key.items():
            (self.root / (role + ".pub.hex")).write_text(key.public_key().public_bytes_raw().hex())
        self.pins = stage.pins(self.root, self.key)
        self.request = {"agent_root": self.pins["agent-authority"], "policy_root": self.pins["kernel-policy"],
                        "web_hash": "a"*64, "reserve_hash": "b"*64}

    def test_policy_signature_scope_and_lifetime(self):
        signed = stage.sign(self.request, self.pins, self.key["kernel-policy"])
        verified = stage.verify_policy(signed, self.request)
        self.assertEqual(verified.revision, 1)
        self.assertEqual(verified.config.kernel_id, stage.AUDIENCE)
        self.assertEqual(verified.config.tools, ("echo",))
        self.assertEqual([a.actor for a in verified.config.agents], ["stage-web", "stage-reserve"])
        self.assertEqual(verified.config.public_keys[stage.KEY_ID].public_key.hex(), self.pins["kernel-issuer"])
        tampered = copy.deepcopy(signed)
        tampered["config"]["port"] = 12026
        with self.assertRaisesRegex(ValueError, "signature"):
            stage.verify_policy(tampered, self.request)
        with self.assertRaises(InvalidSignature):
            stage.sign(self.request, self.pins, self.key["kernel-issuer"])
        with self.assertRaisesRegex(ValueError, "signature"):
            stage.verify_policy(signed, {**self.request, "policy_root": self.pins["kernel-approver"]})
        with self.assertRaisesRegex(ValueError, "enrollment"):
            stage.verify_policy(signed, {**self.request, "web_hash": "c"*64})
        with patch.object(stage, "millis", return_value=verified.expires_at_ms + 1), self.assertRaises(ValueError):
            stage.verify_policy(signed, self.request)

    def test_approver_must_be_distinct_and_present(self):
        pin = self.root / "kernel-approver.pub.hex"
        pin.unlink()
        with self.assertRaises(FileNotFoundError):
            stage.pins(self.root, self.key)
        pin.write_text(self.pins["agent-authority"])
        with self.assertRaisesRegex(ValueError, "distinct"):
            stage.pins(self.root, self.key)

    def test_approved_echo_and_wrong_approval(self):
        args = SimpleNamespace(cmd="draft-echo", keys=self.root, reviewer="operator",
                               draft=self.root / "draft.json", approval=self.root / "approval.json")
        raw = stage.permit_action(args, self.pins)
        stage.save(args.draft, stage.encode(raw))
        args.cmd = "approve-echo"
        with patch.object(stage.sys.stdin, "isatty", return_value=False), self.assertRaisesRegex(ValueError, "human"):
            stage.permit_action(args, self.pins)
        with patch.object(stage.sys.stdin, "isatty", return_value=True), patch.object(stage.sys.stderr, "isatty", return_value=True), \
                patch("builtins.input", return_value="APPROVE " + raw["permit_id"]), \
                patch.object(stage, "signing_material", return_value=(self.key["kernel-approver"], b"")), redirect_stdout(io.StringIO()):
            approval = stage.permit_action(args, self.pins)
        stage.save(args.approval, stage.encode(approval))
        args.cmd = "issue-echo"
        with patch.object(stage, "signing_material", return_value=(self.key["kernel-issuer"], b"")):
            signed = stage.permit_action(args, self.pins)
            with self.assertRaisesRegex(ValueError, "signature"):
                stage.permit_action(args, {**self.pins, "kernel-approver": self.pins["agent-authority"]})
        self.assertEqual(stage.verify_permit(signed, self.pins["kernel-issuer"]).name, "permit-" + raw["permit_id"] + ".json")
        with self.assertRaisesRegex(ValueError, "verification"):
            stage.verify_permit(signed, self.pins["agent-authority"])
        for field, value in (("subject", "stage-reserve"), ("audience", "elsewhere"), ("action", "add")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                stage.verify_permit({**signed, field: value}, self.pins["kernel-issuer"])

    def test_runtime_grant_import_does_not_reuse_first_commissioning_state(self):
        unit = Path("/etc/systemd/system/shards-stage-origin.service")
        first = stage.expected_unit_fields(unit, accepting_grant=False)
        live = stage.expected_unit_fields(unit, accepting_grant=True)
        self.assertEqual(first["ActiveState"], "inactive")
        self.assertEqual(live["ActiveState"], "active")
        for key in ("UnitFileState", "FragmentPath", "DropInPaths", "NeedDaemonReload"):
            self.assertEqual(first[key], live[key])
        self.assertEqual(live["UnitFileState"], "disabled")
        self.assertEqual(live["DropInPaths"], "")

        ledger = self.root / "audit.db"
        kernel = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
        stage.verify_audit_state(ledger, kernel, accepting_grant=False)
        with self.assertRaises(FileNotFoundError):
            stage.verify_audit_state(ledger, kernel, accepting_grant=True)
        ledger.write_bytes(b"existing-audit-must-remain-untouched")
        ledger.chmod(0o600)
        before = ledger.read_bytes()
        stage.verify_audit_state(ledger, kernel, accepting_grant=True)
        self.assertEqual(ledger.read_bytes(), before)
        with self.assertRaisesRegex(ValueError, "unused"):
            stage.verify_audit_state(ledger, kernel, accepting_grant=False)
        ledger.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            stage.verify_audit_state(ledger, kernel, accepting_grant=True)
        ledger.unlink()
        ledger.symlink_to(self.root / "operator.json")
        with self.assertRaises((ValueError, FileNotFoundError)):
            stage.verify_audit_state(ledger, kernel, accepting_grant=True)

    def test_exclusive_private_outputs_and_safe_environment(self):
        path = self.root / "file"
        stage.save(path, b"original")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            stage.save(path, b"replacement")
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            stage.save(link, b"original", resume=True)
        self.assertEqual(path.read_bytes(), b"original")
        for host, token in (("https://agents.shardsinc.co.uk", "a"*32),
                            ("http://stage.example.test", "a"*32), ("https://stage.example.test", "x"*32 + "\nOTHER=x")):
            with self.subTest(host=host), self.assertRaises(ValueError):
                stage.origin_env({"web": "stage-web.synthetic"}, host, "a"*32, token, "b"*32)
        with self.assertRaises(ValueError):
            stage.decode(b'{"x":1,"x":2}')
