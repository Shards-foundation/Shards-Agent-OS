"""Operator CLI for the governed Qwen agent web surface.

Deliberately separate from ``shards-agent-os`` so that the chat surface cannot
be started accidentally by an existing deployment, and so that its
configuration (provider, authority verifier, edge secret) is explicit.

This process holds *no* private signing key and *no* model credential value:
credentials are referenced by environment-variable name only.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Sequence

from .agent_loop import ToolAuthority, ensure_agent_schema, load_bundles
from .agent_state import recover_incomplete_turns
from .qwen_provider import FixtureProvider, provider_from_config
from .tool_permit_authority import public_key_from_file
from .web_server import WebConfig, WebError, make_server, _secret_from_env


def _add_provider_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provider", required=True,
                        choices=("workers-ai", "openai-compatible", "local-transformers"))
    parser.add_argument("--model", default=None,
                        help="Qwen model id (defaults to the provider's default)")
    parser.add_argument("--provider-base-url", default=None,
                        help="OpenAI-compatible base URL, or Workers AI API base")
    parser.add_argument("--provider-credential-env", default=None,
                        help="Name of the env var holding the provider key")
    parser.add_argument("--cf-account-id", default=None,
                        help="Cloudflare account ID for Workers AI")
    parser.add_argument("--max-tokens", type=int, default=None)


def _provider_config(args: argparse.Namespace) -> dict:
    config: dict = {"kind": args.provider}
    if args.model:
        config["model"] = args.model
    if args.provider_base_url:
        config["base_url"] = args.provider_base_url
    if args.provider_credential_env:
        config["credential_env"] = args.provider_credential_env
    if args.cf_account_id:
        config["account_id"] = args.cf_account_id
    if args.max_tokens is not None:
        config["max_tokens"] = args.max_tokens
    return config


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shards-agent-os-agent",
        description="Serve the governed Qwen agent (loopback only; put a trusted edge in front)",
    )
    parser.add_argument("--db", required=True, help="Absolute private SQLite path")
    parser.add_argument("--audience", required=True,
                        help="Instance identifier that authority documents must name")
    parser.add_argument("--authority-public-key-file", required=True,
                        help="Independent authority public verifier (0644)")
    parser.add_argument("--delegation-file", default=None,
                        help="Signed observation delegation (0600)")
    parser.add_argument("--bundle-dir", default=None,
                        help="Directory of signed kernel permit bundles (0600 files)")
    parser.add_argument("--kernel-port", type=int, default=8765,
                        help="Loopback port of the already-running Shards-Kernel operator")
    parser.add_argument("--edge-secret-env", default="SHARDS_EDGE_ASSERTION_SECRET",
                        help="Env var name holding the shared edge assertion secret")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12000)
    parser.add_argument("--edge-public-origin", default=None,
                        help="Explicit HTTPS browser origin trusted behind a signed edge")
    parser.add_argument("--mount-path", choices=("/agent-os",), default="",
                        help="Serve the hub UI under this path and require signed edge requests")
    parser.add_argument("--allow-fixture-provider", action="store_true",
                        help="Unit-test only; never evidence of real inference")
    _add_provider_arguments(parser)
    args = parser.parse_args(argv)

    try:
        if args.allow_fixture_provider:
            provider = FixtureProvider('{"reply":"fixture","tool":null}')
        else:
            provider = provider_from_config(_provider_config(args))
        authority = ToolAuthority(
            public_key_hex=public_key_from_file(args.authority_public_key_file),
            audience=args.audience,
            delegation_file=args.delegation_file,
            bundles=load_bundles(args.bundle_dir),
        )
        ensure_agent_schema(args.db)
        recovered = recover_incomplete_turns(args.db)
        config = WebConfig(
            db_path=args.db, audience=args.audience, provider=provider,
            authority=authority, kernel_port=args.kernel_port,
            edge_secret=_secret_from_env(args.edge_secret_env),
            host=args.host, port=args.port,
            allow_fixture=args.allow_fixture_provider,
            edge_public_origin=args.edge_public_origin, mount_path=args.mount_path,
        )
        server = make_server(config)
    except (WebError, ValueError, OSError) as exc:
        code = getattr(exc, "code", "CONFIGURATION_ERROR")
        print(json.dumps({"status": "REFUSED", "error": code}), file=sys.stderr)
        return 6
    print(json.dumps({
        "status": "listening", "url": f"http://{config.host}:{config.port}/",
        "provider": provider.name, "model": getattr(provider, "model", None),
        "recovered_turns": recovered, "authority": authority.audience,
        "kernel_bundles": len(authority.bundles),
    }), file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
