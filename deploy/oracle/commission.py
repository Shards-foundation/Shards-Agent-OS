"""First commissioning of the two staging units. No service control or network API."""
import argparse
import getpass
import hashlib
import json
import os
import platform
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import warnings
from importlib.metadata import version
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from shards_agent_os.tool_permit_authority import (
    _load_private_key, arguments_digest, issue_kernel_bundle, public_key_from_file, verify_kernel_bundle,
)
from shards_kernel.cli.service import _unique_pairs
from shards_kernel.cli.signed_policy import canonical_policy_payload, verify_signed_policy
from shards_kernel.cli.offline_issuer import issue_approved_permit, sign_operator_approval, validate_narrow_draft
from shards_kernel.integrations.wire import permit_from_mapping, permit_to_mapping
from shards_kernel.permits import PermitBuilder, PublicVerificationKey, verify_signature
from shards_kernel.integrations.auth import agent_token_kdf
from shards_kernel.issuer import sign_operator_policy

CONFIG = Path("/etc/shards-agent-stage")
AUDIT = Path("/var/lib/shards-stage-kernel/audit.sqlite3")
AUDIENCE = "shards-agent-os-oracle-stage"
ISSUER = "stage-operator"
KEY_ID = "stage-permit-issuer"
WEB = "stage-web"
RESERVE = "stage-reserve"
ARGS = {"text": "oracle-stage-acceptance"}
WEEK = 7 * 24 * 3600 * 1000


def require(ok, message):
    if not ok:
        raise ValueError(message)


def millis():
    return time.time_ns() // 1_000_000


def encode(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def decode(data):
    require(len(data) <= 8192, "Oversized input")
    return json.loads(data, object_pairs_hook=_unique_pairs)


def read_line():
    print("Paste the single public JSON line from the other terminal:", file=sys.stderr)
    return decode(sys.stdin.buffer.readline(8193))


def save(path, data, mode=0o600, gid=None, resume=False, uid=None):
    """Publish a complete regular file without replacing anything."""
    parent = path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and not parent.st_mode & 0o022, "Untrusted output directory")
    with tempfile.NamedTemporaryFile(dir=path.parent) as f:
        f.write(data)
        f.flush()
        if gid is not None or uid is not None:
            os.fchown(f.fileno(), -1 if uid is None else uid, -1 if gid is None else gid)
        os.fchmod(f.fileno(), mode)
        os.fsync(f.fileno())
        try:
            os.link(f.name, path)
        except FileExistsError:
            if not resume:
                raise
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == (os.geteuid() if uid is None else uid)
                    and (gid is None or info.st_gid == gid) and stat.S_IMODE(info.st_mode) == mode
                    and info.st_size == len(data) and path.read_bytes() == data,
                    "Existing configuration differs; inspect locally")


def pins(directory, roles):
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and not info.st_mode & 0o022, "Untrusted authority directory")
    keys = {role: public_key_from_file(str(directory / (role + ".pub.hex"))) for role in roles}
    require(len(set(keys.values())) == len(keys), "Authority roles require distinct public keys")
    return keys


def host_preflight():
    require(os.geteuid() == 0, "Use the staging host administrator session")
    release = platform.freedesktop_os_release()
    require(release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04"
            and platform.machine() == "aarch64", "Expected Ubuntu 24.04 ARM64 staging host")
    require(version("shards-kernel") == "0.1.3" and version("shards-agent-os") == "0.3.0",
            "Unexpected staging runtime version")
    accounts = [pwd.getpwnam("shards-stage-" + role) for role in ("kernel", "web")]
    require(len({0, *(a.pw_uid for a in accounts)}) == 3
            and len({0, *(a.pw_gid for a in accounts)}) == 3, "Service identities overlap")
    for account, unit in zip(accounts, ("shards-stage-kernel", "shards-stage-origin")):
        state = Path("/var/lib", account.pw_name).lstat()
        require(stat.S_ISDIR(state.st_mode) and state.st_uid == account.pw_uid
                and state.st_gid == account.pw_gid and stat.S_IMODE(state.st_mode) == 0o700,
                "Private service state directory required")
        name = unit + ".service"
        file = Path("/etc/systemd/system", name)
        info = file.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                and file.read_bytes() == Path(__file__).with_name(name).read_bytes(),
                "Installed unit differs from the reviewed unit")
        fields = subprocess.check_output(["systemctl", "show", name, "-p", "ActiveState",
            "-p", "UnitFileState", "-p", "FragmentPath", "-p", "DropInPaths", "-p", "NeedDaemonReload"], text=True)
        require(dict(line.split("=", 1) for line in fields.splitlines()) ==
                {"ActiveState": "inactive", "UnitFileState": "disabled", "FragmentPath": str(file),
                 "DropInPaths": "", "NeedDaemonReload": "no"}, "Expected inactive, disabled, unmodified units")
    subprocess.run(["systemd-analyze", "verify", *(str(Path("/etc/systemd/system", name + ".service"))
                    for name in ("shards-stage-origin", "shards-stage-kernel"))], check=True)
    require(not os.path.lexists(AUDIT), "First commissioning requires an unused staging audit path")
    parent = CONFIG.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022,
            "Untrusted staging configuration directory")
    keys = []
    for name in ("authority.hex", "kernel-policy.pub.hex"):
        path = CONFIG / name
        info = path.lstat()
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o444, "Expected root-owned 0444 public pin")
        keys.append(public_key_from_file(str(path)))
    require(keys[0] != keys[1], "Agent and policy authorities must differ")
    for account in accounts:
        subprocess.run(["/usr/sbin/runuser", "-u", account.pw_name, "--", "/usr/bin/test", "-x", CONFIG], check=True)
    return keys


def enrollment(keys, create=False):
    path = CONFIG / "enrollment.private.json"
    if create and not os.path.lexists(path):
        for name in ("kernel.env", "origin.env", "operator.json"):
            require(not os.path.lexists(CONFIG / name), "Existing configuration requires reconciliation")
        pepper = secrets.token_hex(48)
        secret = {"pepper": pepper, "api": secrets.token_hex(48), "web": WEB + "." + secrets.token_hex(48),
                  "reserve_hash": agent_token_kdf(RESERVE + "." + secrets.token_hex(48), pepper.encode())}
        save(path, encode(secret))
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 2048, "Invalid private enrollment file")
    secret = decode(path.read_bytes())
    for key in ("api", "pepper"):
        require(re.fullmatch("[0-9a-f]{96}", secret[key]), "Invalid transport material")
    require(re.fullmatch(r"stage-web\.[0-9a-f]{96}", secret["web"]), "Invalid web identity")
    request = {"agent_root": keys[0], "policy_root": keys[1],
               "web_hash": agent_token_kdf(secret["web"], secret["pepper"].encode()),
               "reserve_hash": secret["reserve_hash"]}
    return secret, request


def policy_config(request, issuer):
    fields = {"agent_root", "policy_root", "web_hash", "reserve_hash"}
    require(type(request) is dict and set(request) == fields, "Unexpected enrollment fields")
    values = [*request.values(), issuer]
    require(all(type(v) is str and re.fullmatch("[0-9a-f]{64}", v) for v in values)
            and len(set(values)) == len(values), "Invalid or repeated enrollment or signing identities")
    return {"version": 2, "kernel_id": AUDIENCE, "port": 18765, "audit_db": str(AUDIT),
            "tools": ["echo"], "agents": [
                {"actor": actor, "token_scrypt": request[key], "allowed_tools": ["echo"]}
                for actor, key in ((WEB, "web_hash"), (RESERVE, "reserve_hash"))],
            "issuer_keys": [{"key_id": KEY_ID, "issuer": ISSUER, "public_key_hex": issuer, "revoked": False}]}


def sign(request, keys, key):
    require(request["agent_root"] == keys["agent-authority"] and request["policy_root"] == keys["kernel-policy"],
            "Oracle pins differ from the Chromebook pins")
    now = millis()
    envelope = sign_operator_policy(policy_config(request, keys["kernel-issuer"]), key, revision=1,
                                   issued_at_ms=now, expires_at_ms=now + WEEK)
    # Kernel's full schema verifier also checks the Oracle audit directory exists.
    # Authenticate the signature here and run the full verifier on the target VM.
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys["kernel-policy"])).verify(
        bytes.fromhex(envelope["signature_hex"]), canonical_policy_payload(envelope))
    return envelope


def verify_policy(envelope, request):
    policy = verify_signed_policy(envelope, trusted_public_key_hex=request["policy_root"], current_time_ms=millis())
    issuer = envelope["config"]["issuer_keys"][0]["public_key_hex"]
    require(policy.revision == 1 and policy.expires_at_ms - envelope["issued_at_ms"] == WEEK
            and envelope["config"] == policy_config(request, issuer), "Signed policy differs from host enrollment")
    return policy


def install_policy(envelope, secret, request):
    verify_policy(envelope, request)
    gid = pwd.getpwnam("shards-stage-kernel").pw_gid
    save(CONFIG / "operator.json", encode(envelope), 0o440, gid, resume=True)
    content = (f"SHARDS_KERNEL_API_KEY={secret['api']}\nSHARDS_KERNEL_AGENT_AUTH_PEPPER={secret['pepper']}\n"
               f"SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX={request['policy_root']}\n")
    save(CONFIG / "kernel.env", content.encode(), resume=True)


def origin_env(secret, origin, account, token, assertion):
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    require(len(origin) < 262 and re.fullmatch(rf"https://(?:{label}\.)+{label}", origin)
            and origin != "https://agents.shardsinc.co.uk", "An approved staging HTTPS hostname is required")
    require(re.fullmatch("[0-9a-f]{32}", account), "Invalid Cloudflare account ID")
    for credential in (token, assertion):
        require(re.fullmatch(r"[A-Za-z0-9_./+=-]{32,512}", credential), "Invalid staging credential format")
    require(token != assertion, "Use separate Workers AI and assertion credentials")
    return (f"KERNEL_AUDIENCE={AUDIENCE}\nSTAGING_PUBLIC_ORIGIN={origin}\nCF_ACCOUNT_ID={account}\n"
            f"CF_WORKERS_AI_TOKEN={token}\nSHARDS_EDGE_ASSERTION_SECRET={assertion}\n"
            f"SHARDS_KERNEL_AGENT_TOKEN={secret['web']}\n").encode()


def stage_draft():
    now = millis()
    return (PermitBuilder().issuer(ISSUER).subject(WEB).jurisdiction("default").action("echo").params(ARGS)
            .max_executions(1).valid_from_ms(now).valid_until_ms(now + 600_000)
            .proposal_hash(hashlib.sha256(encode(ARGS)).hexdigest()).build_unsigned_v2(key_id=KEY_ID, audience=AUDIENCE))


def private_artifact(path, *, uploaded=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        require(stat.S_ISREG(info.st_mode) and (uploaded or info.st_uid == os.geteuid())
                and stat.S_IMODE(info.st_mode) == 0o600, "Expected a private 0600 artifact")
        return decode(f.read(8193))


def signing_material(directory, role, pinned):
    require(sys.stdin.isatty() and sys.stderr.isatty(), "Signing requires a local operator terminal")
    phrase = getpass.getpass(role + " passphrase: ").encode()
    key = _load_private_key(str(directory / (role + ".key.pem")), phrase)
    require(key.public_key().public_bytes_raw().hex() == pinned, "Signing identity differs from its pin")
    return key, phrase


def checked_echo(raw):
    draft = permit_from_mapping(raw)
    require(type(draft.max_executions) is int and draft.max_executions == 1 and
            encode(raw) == encode(permit_to_mapping(draft)) and draft.subject == WEB
            and draft.audience == AUDIENCE and draft.action == "echo" and draft.params == ARGS
            and draft.issuer == ISSUER and draft.key_id == KEY_ID and draft.jurisdiction == "default"
            and not draft.constraints and draft.valid_from_ms <= millis() < draft.valid_until_ms,
            "Expected a current exact-call staging echo draft")
    return draft


def permit_action(args, keys):
    if args.cmd == "draft-echo":
        return permit_to_mapping(stage_draft())
    draft = checked_echo(private_artifact(args.draft))
    validate_narrow_draft(draft)
    if args.cmd == "approve-echo":
        require(sys.stdin.isatty() and sys.stderr.isatty(), "Approval requires a local human terminal")
        require(re.fullmatch(r"[A-Za-z0-9_.@+-]{1,128}", args.reviewer), "Invalid reviewer")
        print(encode(permit_to_mapping(draft)).decode().strip())
        require(input("To approve type APPROVE " + draft.permit_id + ": ") == "APPROVE " + draft.permit_id,
                "Exact draft was not approved")
        key, _ = signing_material(args.keys, "kernel-approver", keys["kernel-approver"])
        now = millis()
        return sign_operator_approval(draft, key, reviewer=args.reviewer, approved_at_ms=now,
                                      expires_at_ms=min(now + 300_000, draft.valid_until_ms))
    approval = private_artifact(args.approval)
    key, _ = signing_material(args.keys, "kernel-issuer", keys["kernel-issuer"])
    signed = issue_approved_permit(draft, approval, key, bytes.fromhex(keys["kernel-approver"]),
                                   now_ms=millis(), expected_issuer=ISSUER, expected_key_id=KEY_ID)
    verify_permit(permit_to_mapping(signed), keys["kernel-issuer"])
    return permit_to_mapping(signed)


def verify_permit(raw, issuer):
    signed = checked_echo(raw)
    trusted = PublicVerificationKey(issuer=ISSUER, audience=AUDIENCE, public_key=bytes.fromhex(issuer))
    verified = verify_signature(signed, {}, public_keys={KEY_ID: trusted}, expected_audience=AUDIENCE)
    require(verified.is_allowed(), "Independent permit verification failed")
    return CONFIG / "bundles" / ("permit-" + signed.permit_id + ".json")


def bind_echo(args, keys):
    path = verify_permit(private_artifact(args.permit), keys["kernel-issuer"])
    require(sys.stdin.isatty() and sys.stderr.isatty(), "Binding requires a local operator terminal")
    print("Bind the approved staging echo to Access actor", args.actor)
    require(input("Type BIND STAGE ECHO to confirm: ") == "BIND STAGE ECHO", "Bundle declined")
    _, phrase = signing_material(args.keys, "agent-authority", keys["agent-authority"])
    issue_kernel_bundle(private_key_path=str(args.keys / "agent-authority.key.pem"),
                        passphrase=phrase,
                        output_path=str(args.out.absolute()), permit_file=str(args.permit.absolute()),
                        installed_permit_file=str(path), audience=AUDIENCE, actor=args.actor,
                        tool="kernel.echo", arguments=ARGS, ttl_seconds=300)
    verify_kernel_bundle(private_artifact(args.out), public_key_hex=keys["agent-authority"], audience=AUDIENCE,
                         actor=args.actor, tool="kernel.echo", arguments=ARGS)


def install_echo(args, envelope, request):
    if args.permit is None and args.bundle is None:
        require(sys.stdin.isatty() and sys.stderr.isatty(), "Grant import requires a local terminal")
        permit = decode(getpass.getpass("Paste signed permit JSON: "))
        bundle = decode(getpass.getpass("Paste signed Agent OS bundle JSON: "))
    else:
        require(args.permit is not None and args.bundle is not None, "Supply both grant artifacts")
        permit = private_artifact(args.permit, uploaded=True)
        bundle = private_artifact(args.bundle, uploaded=True)
    path = verify_permit(permit, envelope["config"]["issuer_keys"][0]["public_key_hex"])
    payload = verify_kernel_bundle(bundle, public_key_hex=request["agent_root"], audience=AUDIENCE,
                                   actor=args.actor, tool="kernel.echo", arguments=ARGS)
    require(payload["permit_file"] == str(path), "Unexpected installed permit path")
    web = pwd.getpwnam("shards-stage-web")
    save(path, encode(permit), uid=web.pw_uid, gid=web.pw_gid, resume=True)
    digest = arguments_digest("kernel.echo", ARGS)
    save(path.with_name(digest + ".json"), encode(bundle), uid=web.pw_uid, gid=web.pw_gid, resume=True)


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="cmd", required=True)
    commands.add_parser("enroll")
    commands.add_parser("install-policy")
    commands.add_parser("configure-origin")
    install = commands.add_parser("install-echo")
    install.add_argument("--permit", type=Path)
    install.add_argument("--bundle", type=Path)
    install.add_argument("--actor", required=True)
    offline = ("sign-policy", "draft-echo", "approve-echo", "issue-echo", "bind-echo")
    for name in offline:
        sub = commands.add_parser(name)
        sub.add_argument("--keys", type=Path, default=Path.home() / ".shards-authority")
        sub.add_argument("--out", type=Path, required=True)
        if name == "bind-echo":
            sub.add_argument("--permit", type=Path, required=True)
            sub.add_argument("--actor", required=True)
        if name in ("approve-echo", "issue-echo"):
            sub.add_argument("--draft", type=Path, required=True)
        if name == "approve-echo":
            sub.add_argument("--reviewer", required=True)
        if name == "issue-echo":
            sub.add_argument("--approval", type=Path, required=True)
    args = parser.parse_args()
    if args.cmd in offline:
        roles = ["agent-authority", "kernel-policy", "kernel-issuer"]
        if args.cmd != "sign-policy":
            keys = pins(args.keys, [*roles, "kernel-approver"])
            if args.cmd == "bind-echo":
                bind_echo(args, keys)
            else:
                save(args.out.absolute(), encode(permit_action(args, keys)))
            return
        keys = pins(args.keys, roles)
        request = read_line()
        config = policy_config(request, keys["kernel-issuer"])
        require(keys["agent-authority"] == request["agent_root"] and keys["kernel-policy"] == request["policy_root"],
                "Installed trust roots differ from Chromebook pins")
        require(sys.stdin.isatty() and sys.stderr.isatty(), "Signing requires a local operator terminal")
        print(f"Review revision 1, seven days, echo only, {AUDIENCE}, {WEB} and disabled-by-secret-discard {RESERVE}.")
        print("Enrolled issuer public key:", config["issuer_keys"][0]["public_key_hex"])
        require(input("Type SIGN STAGE POLICY to confirm: ") == "SIGN STAGE POLICY", "Policy signature declined")
        key, _ = signing_material(args.keys, "kernel-policy", keys["kernel-policy"])
        envelope = sign(request, keys, key)
        save(args.out.absolute(), encode(envelope))
        print(encode(envelope).decode().strip())
        return

    keys = host_preflight()
    secret, request = enrollment(keys, create=args.cmd == "enroll")
    if args.cmd == "enroll":
        print(encode(request).decode().strip())
    elif args.cmd == "install-policy":
        install_policy(read_line(), secret, request)
        print("Verified and installed revision 1. Both services remain stopped.")
    else:
        envelope = decode((CONFIG / "operator.json").read_bytes())
        install_policy(envelope, secret, request)
        if args.cmd == "install-echo":
            install_echo(args, envelope, request)
            return
        require(sys.stdin.isatty() and sys.stderr.isatty(), "Provisioning requires an operator terminal")
        content = origin_env(secret, input("Approved staging HTTPS origin: "), input("Cloudflare account ID: "),
                             getpass.getpass("Scoped staging Workers AI token: "),
                             getpass.getpass("Matching staging Worker assertion secret: "))
        bundles = CONFIG / "bundles"
        if not os.path.lexists(bundles):
            bundles.mkdir(mode=0o755)
            bundles.chmod(0o755)
        info = bundles.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                and not any(bundles.iterdir()), "Expected an empty administrator-managed bundles directory")
        subprocess.run(["/usr/sbin/runuser", "-u", "shards-stage-web", "--", "test", "-r", bundles], check=True)
        subprocess.run(["/usr/sbin/runuser", "-u", "shards-stage-web", "--", "test", "-x", bundles], check=True)
        save(CONFIG / "origin.env", content, resume=True)
        print("Verified local configuration. Both services remain stopped.")


if __name__ == "__main__":
    warnings.simplefilter("error", getpass.GetPassWarning)
    try:
        cli()
    except (OSError, ValueError, TypeError, KeyError, IndexError, getpass.GetPassWarning, InvalidSignature, subprocess.SubprocessError) as exc:
        # External parsers can include untrusted values in errors. Never echo input or credentials.
        sys.exit("Commissioning refused (" + type(exc).__name__ + "). Check pins, input, permissions and unit state.")
