"""Offline authority CLI for Agent OS tool delegation and kernel permit bundles.

Run this on a separately trusted approval workstation. It is deliberately not
reachable from the web server, holds the only private authority key, and never
runs inside the process that serves requests.

The Agent OS host is given the *public* verifier only (``--authority-public-key-file``).
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import Sequence

from .tool_permit_authority import (
    AuthorityError, describe, generate_authority_key, issue_delegation,
    issue_kernel_bundle, load_signed_document, public_key_from_file,
)


def _passphrase(*, confirm: bool) -> bytes:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise PermissionError("Offline authority signing requires an interactive terminal")
    value = getpass.getpass("Authority signing-key passphrase: ").encode("utf-8")
    if not 16 <= len(value) <= 1024:
        raise ValueError("A strong passphrase is required")
    if confirm and getpass.getpass("Confirm passphrase: ").encode("utf-8") != value:
        raise ValueError("Passphrase confirmation failed")
    return value


def _parse_arguments(raw: str) -> dict:
    try:
        value = json.loads(raw)
    except ValueError:
        raise ValueError("Arguments must be a JSON object") from None
    if type(value) is not dict:
        raise ValueError("Arguments must be a JSON object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shards-agent-os-authority",
        description="OFFLINE independent tool authority; never run on the web-serving host",
    )
    actions = parser.add_subparsers(dest="action", required=True)

    keygen = actions.add_parser("keygen", help="Create the independent authority identity")
    keygen.add_argument("--private-key-file", required=True)
    keygen.add_argument("--public-key-file", required=True)

    show = actions.add_parser("show", help="Print a signed document without its signature")
    show.add_argument("--document", required=True)

    delegate = actions.add_parser(
        "delegate", help="Authorise read-only observation tools for one actor",
    )
    delegate.add_argument("--private-key-file", required=True)
    delegate.add_argument("--output", required=True)
    delegate.add_argument("--audience", required=True, help="Agent OS instance identifier")
    delegate.add_argument("--actor", required=True)
    delegate.add_argument("--tool", action="append", required=True,
                          choices=("os.queue_summary", "os.halt_state"))
    delegate.add_argument("--max-executions", type=int, default=200)
    delegate.add_argument("--ttl-seconds", type=int, default=86_400)

    bundle = actions.add_parser(
        "bind-kernel", help="Attest one already-signed kernel permit for one exact call",
    )
    bundle.add_argument("--private-key-file", required=True)
    bundle.add_argument("--output", required=True)
    bundle.add_argument("--permit-file", required=True,
                        help="Operator-signed Shards-Kernel v2 permit (0600)")
    bundle.add_argument("--audience", required=True)
    bundle.add_argument("--actor", required=True)
    bundle.add_argument("--tool", required=True, choices=("kernel.echo", "kernel.add"))
    bundle.add_argument("--arguments-json", required=True)
    bundle.add_argument("--ttl-seconds", type=int, default=900)

    verify = actions.add_parser("verify", help="Verify a document against a public key")
    verify.add_argument("--public-key-file", required=True)
    verify.add_argument("--document", required=True)

    args = parser.parse_args(argv)
    try:
        if args.action == "keygen":
            result = generate_authority_key(
                private_path=args.private_key_file, public_path=args.public_key_file,
                passphrase=_passphrase(confirm=True),
            )
        elif args.action == "show":
            result = describe(load_signed_document(args.document))
        elif args.action == "delegate":
            result = issue_delegation(
                private_key_path=args.private_key_file, passphrase=_passphrase(confirm=False),
                output_path=args.output, audience=args.audience, actor=args.actor,
                tools=list(dict.fromkeys(args.tool)), max_executions=args.max_executions,
                ttl_seconds=args.ttl_seconds,
            )
        elif args.action == "bind-kernel":
            result = issue_kernel_bundle(
                private_key_path=args.private_key_file, passphrase=_passphrase(confirm=False),
                output_path=args.output, permit_file=args.permit_file,
                audience=args.audience, actor=args.actor, tool=args.tool,
                arguments=_parse_arguments(args.arguments_json),
                ttl_seconds=args.ttl_seconds,
            )
        else:
            from .tool_permit_authority import verify_signed, GRANT_DOMAIN, BUNDLE_DOMAIN

            document = load_signed_document(args.document)
            kind = document.get("kind")
            domain = GRANT_DOMAIN if kind == "observation-delegation" else BUNDLE_DOMAIN
            payload = verify_signed(
                document, public_key_hex=public_key_from_file(args.public_key_file),
                domain=domain,
            )
            result = {"verified": True, "kind": payload.get("kind"),
                      "actor": payload.get("actor"), "audience": payload.get("audience")}
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    except (AuthorityError, ValueError, OSError, PermissionError):
        print('{"ok":false,"error":"Authority operation refused"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
