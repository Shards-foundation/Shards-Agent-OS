"""Replaceable Qwen model-provider interface.

Three interchangeable transports, selected by configuration:

``workers-ai``
    Cloudflare Workers AI REST inference for a Qwen model. The account ID and
    API token are read from the process environment by *name*; they are never
    accepted from a request, a stored row, a log line or an HTML page.

``openai-compatible``
    Any OpenAI-compatible ``/chat/completions`` endpoint that serves Qwen, for
    non-Cloudflare staging or local development.

``local-transformers``
    Real in-process Qwen inference through ``transformers`` (optional extra
    ``local-qwen``). Used to obtain genuine model output on a controlled host
    when no hosted credential is available.

Nothing in this module issues authority. A provider reply is untrusted text;
:mod:`shards_agent_os.agent_protocol` decides what, if anything, it may ask
for, and :mod:`shards_agent_os.tool_permit_authority` decides whether that
request is permitted.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

# Local inference dtypes. float32 is the safe default; bfloat16 halves the
# resident weight size on a constrained host, and bfloat16 keeps the exponent
# range of float32 so greedy decoding stays stable.
_TORCH_DTYPES = ("float32", "bfloat16", "float16")

MAX_PROVIDER_RESPONSE_BYTES = 262_144
DEFAULT_MAX_TOKENS = 400
PROVIDER_KINDS = ("workers-ai", "openai-compatible", "local-transformers", "fixture")

# Workers AI model names are namespaced with a leading "@" (e.g.
# "@cf/qwen/qwen3.8-27b"); Hugging Face ids start with an alphanumeric.
_MODEL_NAME = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9_.:/@-]{1,127}\Z")
_ACCOUNT_ID = re.compile(r"[0-9a-f]{32}\Z")
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,63}\Z")


class ProviderError(RuntimeError):
    """Raised with a coarse, non-sensitive code. Never carries a key or body."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ModelReply:
    text: str
    provider: str
    model: str
    latency_ms: int


class ModelProvider(Protocol):
    name: str
    model: str

    def complete(self, *, system: str, user: str, timeout_s: float) -> ModelReply:
        """Return one bounded completion. Raise ProviderError on any failure."""


def _validate_timeout(timeout_s: float) -> float:
    if type(timeout_s) not in (int, float) or not 1.0 <= float(timeout_s) <= 120.0:
        raise ValueError("Provider timeout must be between 1 and 120 seconds")
    return float(timeout_s)


def _https_only(url: str) -> str:
    """Permit https everywhere and plain http only for an explicit loopback."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        return url
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "::1", "localhost"):
        return url
    raise ValueError("Model endpoints must use https (http only on loopback)")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could move a bearer token to another origin; refuse it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise ProviderError("PROVIDER_REDIRECT_REFUSED")


def _post_json(url: str, payload: dict, headers: dict[str, str], timeout_s: float) -> dict:
    body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST", headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout_s) as response:
            if response.status != 200:
                raise ProviderError("PROVIDER_HTTP_STATUS")
            raw = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
    except ProviderError:
        raise
    except urllib.error.HTTPError as exc:
        # Never surface the response body: it can echo request content.
        raise ProviderError(f"PROVIDER_HTTP_{int(exc.code)}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ProviderError("PROVIDER_UNREACHABLE") from None
    if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
        raise ProviderError("PROVIDER_RESPONSE_TOO_LARGE")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ProviderError("PROVIDER_INVALID_JSON") from None
    if type(decoded) is not dict:
        raise ProviderError("PROVIDER_INVALID_JSON")
    return decoded


def _env_secret(name: str) -> str:
    """Read a credential by environment *variable name*, never by value."""
    if type(name) is not str or not _ENV_NAME.fullmatch(name):
        raise ValueError("Credential must be named by an upper-case environment variable")
    value = os.environ.get(name)
    if not value or len(value) < 16:
        raise ProviderError("PROVIDER_CREDENTIAL_MISSING")
    return value


class WorkersAIProvider:
    """Cloudflare Workers AI inference for a Qwen model over the public REST API."""

    name = "workers-ai"

    def __init__(
        self, *, account_id: str, model: str = "@cf/qwen/qwen3.8-27b",
        credential_env: str = "CF_WORKERS_AI_TOKEN", max_tokens: int = DEFAULT_MAX_TOKENS,
        base_url: str = "https://api.cloudflare.com/client/v4",
    ) -> None:
        if type(account_id) is not str or not _ACCOUNT_ID.fullmatch(account_id):
            raise ValueError("A 32-hex Cloudflare account ID is required")
        if type(model) is not str or not _MODEL_NAME.fullmatch(model):
            raise ValueError("Invalid Qwen model identifier")
        if not model.startswith("@cf/qwen/"):
            raise ValueError("Only @cf/qwen/* models are permitted by this provider")
        if type(max_tokens) is not int or not 1 <= max_tokens <= 1024:
            raise ValueError("max_tokens must be 1..1024")
        self.account_id = account_id
        self.model = model
        self.credential_env = credential_env
        self.max_tokens = max_tokens
        self.base_url = _https_only(base_url.rstrip("/"))

    def complete(self, *, system: str, user: str, timeout_s: float) -> ModelReply:
        timeout_s = _validate_timeout(timeout_s)
        token = _env_secret(self.credential_env)
        payload = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.1,
        }
        url = f"{self.base_url}/accounts/{self.account_id}/ai/run/{self.model}"
        started = time.monotonic()
        decoded = _post_json(
            url, payload,
            {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            timeout_s,
        )
        if decoded.get("success") is False:
            raise ProviderError("PROVIDER_REFUSED")
        result = decoded.get("result")
        text = _extract_text(result)
        return ModelReply(
            text=text, provider=self.name, model=self.model,
            latency_ms=int((time.monotonic() - started) * 1000),
        )


class OpenAICompatibleProvider:
    """Any OpenAI-compatible ``/chat/completions`` endpoint serving Qwen."""

    name = "openai-compatible"

    def __init__(
        self, *, base_url: str, model: str = "Qwen/Qwen2.5-1.5B-Instruct",
        credential_env: str | None = None, max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self.base_url = _https_only(base_url.rstrip("/"))
        if type(model) is not str or not _MODEL_NAME.fullmatch(model):
            raise ValueError("Invalid model identifier")
        if credential_env is not None and not _ENV_NAME.fullmatch(str(credential_env)):
            raise ValueError("Credential must be named by an environment variable")
        if type(max_tokens) is not int or not 1 <= max_tokens <= 1024:
            raise ValueError("max_tokens must be 1..1024")
        self.model = model
        self.credential_env = credential_env
        self.max_tokens = max_tokens

    def complete(self, *, system: str, user: str, timeout_s: float) -> ModelReply:
        timeout_s = _validate_timeout(timeout_s)
        headers = {"Content-Type": "application/json"}
        if self.credential_env:
            headers["Authorization"] = "Bearer " + _env_secret(self.credential_env)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.1,
        }
        started = time.monotonic()
        decoded = _post_json(f"{self.base_url}/chat/completions", payload, headers, timeout_s)
        choices = decoded.get("choices")
        if type(choices) is not list or not choices or type(choices[0]) is not dict:
            raise ProviderError("PROVIDER_INVALID_JSON")
        message = choices[0].get("message")
        text = _extract_text(message)
        return ModelReply(
            text=text, provider=self.name, model=self.model,
            latency_ms=int((time.monotonic() - started) * 1000),
        )


def _extract_text(node: Any) -> str:
    """Pull plain text out of either wire shape, without trusting its content."""
    if type(node) is str:
        text = node
    elif type(node) is dict:
        candidate = node.get("response", node.get("content"))
        text = candidate if type(candidate) is str else None
        if text is None:
            raise ProviderError("PROVIDER_INVALID_JSON")
    else:
        raise ProviderError("PROVIDER_INVALID_JSON")
    if not text.strip():
        raise ProviderError("PROVIDER_EMPTY_REPLY")
    if len(text) > 32768:
        raise ProviderError("PROVIDER_REPLY_TOO_LARGE")
    return text


class LocalTransformersProvider:
    """Real Qwen inference in-process, for a controlled host with no credential.

    Requires the optional ``local-qwen`` extra. Weights come from the Hugging
    Face cache or a local directory; no credential is embedded anywhere.
    """

    name = "local-transformers"

    def __init__(
        self, *, model: str = "Qwen/Qwen2.5-1.5B-Instruct", max_tokens: int = 220,
        revision: str | None = None, dtype: str = "float32",
    ) -> None:
        if type(model) is not str or not _MODEL_NAME.fullmatch(model):
            raise ValueError("Invalid model identifier")
        if type(max_tokens) is not int or not 1 <= max_tokens <= 1024:
            raise ValueError("max_tokens must be 1..1024")
        if dtype not in _TORCH_DTYPES:
            raise ValueError("dtype must be one of " + ", ".join(_TORCH_DTYPES))
        self.model = model
        self.max_tokens = max_tokens
        self.revision = revision
        self.dtype = dtype
        self._tokenizer = None
        self._model = None

    def _load(self):
        if self._model is not None:
            return
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError:  # pragma: no cover - exercised only without the extra
            raise ProviderError("PROVIDER_DEPENDENCY_MISSING") from None
        kwargs = {"revision": self.revision} if self.revision else {}
        self._tokenizer = AutoTokenizer.from_pretrained(self.model, **kwargs)
        self._model = AutoModelForCausalLM.from_pretrained(
            self.model, dtype=getattr(torch, self.dtype), **kwargs
        )
        self._model.eval()

    def complete(self, *, system: str, user: str, timeout_s: float) -> ModelReply:
        timeout_s = _validate_timeout(timeout_s)
        self._load()
        import torch

        prompt = self._tokenizer.apply_chat_template(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            tokenize=False, add_generation_prompt=True,
        )
        inputs = self._tokenizer(prompt, return_tensors="pt")
        started = time.monotonic()
        with torch.no_grad():
            output = self._model.generate(
                **inputs, max_new_tokens=self.max_tokens, do_sample=False,
                pad_token_id=self._tokenizer.eos_token_id,
            )
        text = self._tokenizer.decode(
            output[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
        )
        latency_ms = int((time.monotonic() - started) * 1000)
        if not text.strip():
            raise ProviderError("PROVIDER_EMPTY_REPLY")
        return ModelReply(text=text, provider=self.name, model=self.model,
                          latency_ms=latency_ms)


class FixtureProvider:
    """Deterministic provider for unit tests only.

    It is never a default and the web server refuses to start with it unless
    ``--allow-fixture-provider`` is passed explicitly, so it cannot be mistaken
    for evidence of real inference.
    """

    name = "fixture"
    model = "fixture/deterministic"

    def __init__(self, replies: list[str] | str, *, latency_ms: int = 1) -> None:
        self._replies = [replies] if type(replies) is str else list(replies)
        self._index = 0
        self.latency_ms = latency_ms
        self.calls: list[dict[str, str]] = []

    def complete(self, *, system: str, user: str, timeout_s: float) -> ModelReply:
        _validate_timeout(timeout_s)
        self.calls.append({"system": system, "user": user})
        if not self._replies:
            raise ProviderError("PROVIDER_EMPTY_REPLY")
        text = self._replies[min(self._index, len(self._replies) - 1)]
        self._index += 1
        return ModelReply(text=text, provider=self.name, model=self.model,
                          latency_ms=self.latency_ms)


def provider_from_config(config: Mapping[str, Any]) -> ModelProvider:
    """Build a provider from a validated mapping.

    Credentials are referenced by environment-variable name only, so a config
    file, a database row or a log line can never contain a key.
    """
    if not isinstance(config, Mapping):
        raise ValueError("Provider configuration must be a mapping")
    kind = config.get("kind")
    if kind == "workers-ai":
        return WorkersAIProvider(
            account_id=config["account_id"], model=config.get("model", "@cf/qwen/qwen3.8-27b"),
            credential_env=config.get("credential_env", "CF_WORKERS_AI_TOKEN"),
            max_tokens=config.get("max_tokens", DEFAULT_MAX_TOKENS),
            base_url=config.get("base_url", "https://api.cloudflare.com/client/v4"),
        )
    if kind == "openai-compatible":
        return OpenAICompatibleProvider(
            base_url=config["base_url"], model=config.get("model", "Qwen/Qwen2.5-1.5B-Instruct"),
            credential_env=config.get("credential_env"),
            max_tokens=config.get("max_tokens", DEFAULT_MAX_TOKENS),
        )
    if kind == "local-transformers":
        return LocalTransformersProvider(
            model=config.get("model", "Qwen/Qwen2.5-1.5B-Instruct"),
            max_tokens=config.get("max_tokens", 220),
            revision=config.get("revision"),
            dtype=config.get("dtype", "float32"),
        )
    raise ValueError("Unsupported provider kind")
