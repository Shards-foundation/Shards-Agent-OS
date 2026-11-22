"""Strictly allowlisted read-only tools and the model's tool-request schema.

Every tool here is read-only and every tool here is *independently governed*.
Two governance classes exist, and the distinction is deliberate:

``observation``
    ``os.queue_summary`` and ``os.halt_state``. No permit exists in Shards
    because there is no side effect. They are still gated by an
    owner-scoped, one-use **observation grant** signed by a separate authority
    key (:mod:`shards_agent_os.tool_permit_authority`), so a model cannot call
    them by merely naming them.

``kernel``
    ``kernel.echo`` and ``kernel.add``. These dispatch through the existing
    Shards-Kernel ``mcp-call`` path and require a signed one-use **permit**
    bound to the exact tool and arguments. The Agent OS never mints these.

There is no shell, network, filesystem, GitHub-write, wallet or
arbitrary-tool capability in this registry, and there is no way to add one
from a request, a config file or model output.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Callable

MAX_ARGUMENT_BYTES = 2048
MAX_TOOL_NAME = 64

_IDENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")


class ToolRejected(ValueError):
    """Raised for any non-allowlisted or schema-invalid tool request."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ToolSpec:
    name: str
    governance: str          # "observation" | "kernel"
    description: str
    schema: dict[str, str]   # argument name -> "str" | "number"
    required: tuple[str, ...]
    render: Callable[[dict], str]

    def validate(self, arguments: Any) -> dict:
        if type(arguments) is not dict:
            raise ToolRejected("TOOL_ARGUMENTS_NOT_OBJECT")
        if set(arguments) != set(self.schema):
            raise ToolRejected("TOOL_ARGUMENTS_SCHEMA_MISMATCH")
        for key in self.required:
            if key not in arguments:
                raise ToolRejected("TOOL_ARGUMENT_MISSING")
        checked: dict[str, Any] = {}
        for key, kind in self.schema.items():
            value = arguments[key]
            if kind == "str":
                if type(value) is not str or not 1 <= len(value) <= 256:
                    raise ToolRejected("TOOL_ARGUMENT_INVALID")
                if any(ord(ch) < 0x20 for ch in value):
                    raise ToolRejected("TOOL_ARGUMENT_INVALID")
                checked[key] = value
            elif kind == "number":
                if type(value) not in (int, float) or not math.isfinite(value):
                    raise ToolRejected("TOOL_ARGUMENT_INVALID")
                if abs(value) > 1_000_000:
                    raise ToolRejected("TOOL_ARGUMENT_OUT_OF_RANGE")
                checked[key] = value
            else:  # pragma: no cover - registry is static
                raise ToolRejected("TOOL_SCHEMA_CORRUPT")
        encoded = json.dumps(checked, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            raise ToolRejected("TOOL_ARGUMENTS_TOO_LARGE")
        return checked


def _render_queue_summary(result: dict) -> str:
    jobs = result.get("jobs") or {}
    summary = ", ".join(f"{status.lower()} {count}" for status, count in sorted(jobs.items()))
    halted = "halted" if result.get("dispatch_halted") else "running"
    return f"Dispatch is {halted}; local jobs: {summary or 'none'}."


def _render_halt_state(result: dict) -> str:
    return "Dispatch is halted." if result.get("dispatch_halted") else "Dispatch is not halted."


def _render_echo(result: dict) -> str:
    return f"The reference echo tool returned {result.get('result')!r}."


def _render_add(result: dict) -> str:
    return f"The reference add tool returned {result.get('result')}."


TOOLS: dict[str, ToolSpec] = {
    "os.queue_summary": ToolSpec(
        name="os.queue_summary", governance="observation",
        description="Read-only count of local dispatch jobs and the halt latch.",
        schema={}, required=(), render=_render_queue_summary,
    ),
    "os.halt_state": ToolSpec(
        name="os.halt_state", governance="observation",
        description="Read-only operator halt-latch state.",
        schema={}, required=(), render=_render_halt_state,
    ),
    "kernel.echo": ToolSpec(
        name="kernel.echo", governance="kernel",
        description="Side-effect-free Shards-Kernel reference tool under a one-use signed permit.",
        schema={"text": "str"}, required=("text",), render=_render_echo,
    ),
    "kernel.add": ToolSpec(
        name="kernel.add", governance="kernel",
        description="Adds two numbers using the Shards-Kernel reference tool under a one-use signed permit.",
        schema={"a": "number", "b": "number"}, required=("a", "b"), render=_render_add,
    ),
}

# The only names the model is told about. Ordering is stable for the prompt.
TOOL_NAMES: tuple[str, ...] = ("os.queue_summary", "os.halt_state", "kernel.echo", "kernel.add")


def tool(name: object) -> ToolSpec:
    """Resolve an allowlisted tool or raise. There is no dynamic registration."""
    if type(name) is not str or len(name) > MAX_TOOL_NAME or not _IDENT.fullmatch(name):
        raise ToolRejected("TOOL_NAME_INVALID")
    spec = TOOLS.get(name)
    if spec is None:
        raise ToolRejected("TOOL_NOT_ALLOWLISTED")
    return spec


def describe_for_prompt() -> str:
    lines = []
    for name in TOOL_NAMES:
        spec = TOOLS[name]
        args = ", ".join(f"{key}:{kind}" for key, kind in spec.schema.items()) or "no arguments"
        lines.append(f"- {name} ({args}): {spec.description}")
    return "\n".join(lines)


def kernel_tool_arguments(spec: ToolSpec, arguments: dict) -> tuple[str, dict]:
    """Map an allowlisted name to the kernel's own tool name and exact arguments."""
    if spec.governance != "kernel":  # pragma: no cover - guarded by callers
        raise ToolRejected("TOOL_NOT_KERNEL")
    if spec.name == "kernel.echo":
        return "echo", {"text": arguments["text"]}
    if spec.name == "kernel.add":
        return "add", {"a": arguments["a"], "b": arguments["b"]}
    raise ToolRejected("TOOL_NOT_ALLOWLISTED")  # pragma: no cover
