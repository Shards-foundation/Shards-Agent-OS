"""Parse the model's structured reply into a reply plus an optional tool request.

The model is asked for exactly one JSON object. It is untrusted text: any
deviation is a hard rejection, never a "best effort" interpretation. In
particular there is no regex extraction of a code block, no retry-with-fixup
and no partial acceptance, because each of those turns malformed output into
authority.

Prompt injection is handled structurally rather than by filtering. Injected
text can at most produce an allowlisted tool name with schema-valid arguments;
:mod:`shards_agent_os.agent_loop` then requires an independently signed grant
or permit before anything runs. A reply that names a non-allowlisted tool is
recorded as a denial, so the attempt is visible rather than silently dropped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

MAX_MODEL_OUTPUT = 16384
_REPLY_LIMIT = 4000

_FENCE = re.compile(r"\A\s*```(?:json)?\s*(.*?)\s*```\s*\Z", re.DOTALL)


class ProtocolError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ModelDecision:
    reply: str
    tool_name: str | None
    arguments: dict | None


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("MODEL_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str):
    raise ProtocolError("MODEL_NONFINITE_NUMBER")


def parse_decision(text: str) -> ModelDecision:
    """Return the parsed decision or raise :class:`ProtocolError`.

    Accepted shapes, and nothing else::

        {"reply": "...", "tool": null}
        {"reply": "...", "tool": {"name": "...", "arguments": {...}}}
    """
    if type(text) is not str:
        raise ProtocolError("MODEL_OUTPUT_NOT_TEXT")
    if len(text) > MAX_MODEL_OUTPUT:
        raise ProtocolError("MODEL_OUTPUT_TOO_LARGE")
    candidate = text.strip()
    fenced = _FENCE.match(candidate)
    if fenced:
        candidate = fenced.group(1)
    try:
        parsed = json.loads(
            candidate, object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (ValueError, TypeError):
        raise ProtocolError("MODEL_OUTPUT_NOT_JSON") from None
    if type(parsed) is not dict or set(parsed) != {"reply", "tool"}:
        raise ProtocolError("MODEL_OUTPUT_SCHEMA_MISMATCH")
    reply = parsed["reply"]
    if type(reply) is not str or not reply.strip():
        raise ProtocolError("MODEL_REPLY_INVALID")
    tool = parsed["tool"]
    if tool is None:
        return ModelDecision(reply=reply.strip()[:_REPLY_LIMIT], tool_name=None, arguments=None)
    if type(tool) is not dict or set(tool) != {"name", "arguments"}:
        raise ProtocolError("MODEL_TOOL_SCHEMA_MISMATCH")
    name, arguments = tool["name"], tool["arguments"]
    if type(name) is not str or not name:
        raise ProtocolError("MODEL_TOOL_SCHEMA_MISMATCH")
    if type(arguments) is not dict:
        raise ProtocolError("MODEL_TOOL_ARGUMENTS_NOT_OBJECT")
    return ModelDecision(reply=reply.strip()[:_REPLY_LIMIT], tool_name=name, arguments=arguments)
