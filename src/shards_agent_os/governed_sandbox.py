"""Bind OS sandbox workloads to Shards-Kernel's signed MCP permit boundary.

This adapter belongs in a trusted host process with a protected Docker socket.
It never issues permits, grants an actor identity or exposes an unauthenticated
sandbox RPC. Deploy it under a separate service identity from untrusted agents.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from shards_kernel.api import StrictKernel
from shards_kernel.integrations.mcp_sdk_v2 import create_official_mcp_server

from .sandbox_executor import ExecutionSpec, GVisorExecutor

TOOL_NAME = "sandbox.exec"


def make_sandbox_handler(runner: GVisorExecutor):
    """Return one trusted handler reused by local MCP and AF_UNIX broker."""
    if not isinstance(runner, GVisorExecutor):
        raise TypeError("A trusted GVisorExecutor is required")

    def sandbox_execute(
        image: str,
        argv: list[str],
        timeout_seconds: int,
        memory_megabytes: int,
        cpu_millicores: int,
        pids_limit: int,
    ) -> dict[str, Any]:
        if type(argv) is not list:
            raise ValueError("Authorised argv must be a JSON array")
        spec = ExecutionSpec(
            image=image,
            argv=tuple(argv),
            timeout_seconds=timeout_seconds,
            memory_megabytes=memory_megabytes,
            cpu_millicores=cpu_millicores,
            pids_limit=pids_limit,
        )
        result = runner.run(spec)
        return asdict(result)
    return sandbox_execute


def create_governed_sandbox_server(
    kernel: StrictKernel, *,
    actor: str,
    executor: GVisorExecutor | None = None,
) -> Any:
    """Create a *local* MCP server where execution requires kernel ALLOW.

    The caller supplies a booted, strictly allowlisted kernel with pinned
    public-only Ed25519 verification keys and a trusted fixed actor.

    Every ExecutionSpec parameter is REQUIRED: defaults must not silently
    expand an issuer's authorised action. The kernel commits the execution
    intent to its ledger before invoking the registered trusted handler.
    """
    if not isinstance(kernel, StrictKernel):
        raise TypeError("sandbox.exec requires StrictKernel")
    if not kernel._public_verifiers or kernel._keyring:
        raise ValueError("sandbox.exec requires public-only Ed25519 permit verification")
    runner = GVisorExecutor() if executor is None else executor
    if not isinstance(runner, GVisorExecutor):
        raise TypeError("A trusted GVisorExecutor is required")

    handler = make_sandbox_handler(runner)
    return create_official_mcp_server(
        kernel, actor=actor, handlers={TOOL_NAME: handler}
    )
