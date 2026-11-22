# Hugging Face inference acceptance

The governed Qwen agent can use the existing `openai-compatible` adapter with
Hugging Face Inference Providers. Add these flags to an already configured
`shards-agent-os-agent` instance.

```bash
--provider openai-compatible \
--provider-base-url https://router.huggingface.co/v1 \
--provider-credential-env HF_TOKEN \
--model "$SHARDS_HF_LIVE_MODEL" \
--max-tokens 128
```

The adapter appends `/chat/completions` to this base URL and uses a
non-streaming POST. Set `SHARDS_HF_LIVE_MODEL` to a Qwen model ID that Hugging
Face currently routes for chat completion. The route can include a Hugging
Face provider suffix. Inject `HF_TOKEN` into the process environment from a
trusted secret store using a fine-grained Hugging Face token with permission
to call Inference Providers. The CLI takes the variable name. [Hugging Face chat completion API](https://huggingface.co/docs/inference-providers/en/tasks/chat-completion)

The response must have one assistant choice with non-empty string
`message.content` and `finish_reason: "stop"`. The adapter discards reasoning
metadata and rejects native tool/function calls, filtering, truncation,
streaming chunks and legacy text-generation responses. The governed loop
parses the assistant text with the existing model-decision schema. A valid
tool request still needs independent authority for the exact tool and arguments
before the loop can queue a kernel job.

## Offline checks

```bash
python -m pip install -e '.[kernel]'
python -Werror::ResourceWarning -m unittest tests.test_huggingface_provider -v
```

The fixtures exercise the CLI provider flags, the generated URL and request,
the response parser, and denial of an assistant-proposed kernel call without
an exact signed bundle. The hosted smoke test skips by default.

## Optional hosted smoke test

Run only after an operator confirms the chosen Qwen route is available to the
configured token and approves the budget for one short request with up to
128 output tokens. Confirm current route pricing against that budget before
opting in. Inject `HF_TOKEN` and set `SHARDS_HF_LIVE_MODEL` privately in the
environment. Replace the example `0.01` below with the approved USD amount.

```bash
SHARDS_HF_LIVE=1 SHARDS_HF_LIVE_APPROVED_USD=0.01 \
  python -m unittest \
  tests.test_huggingface_provider.HuggingFaceLiveAcceptanceTests -v
```

A malformed or missing token, Qwen model setting or positive finite budget
fails preflight before the request. The USD amount records the operator's
approval. Any billing ceiling must be enforced provider-side. The test makes
one request with a 30-second socket timeout, checks the expected answer through
the strict decision parser, and requests no tool. It starts no Agent OS server
or kernel job.

## Evidence scope

The recorded Qwen 0.5B reply and Qwen 3B signed-kernel allow, denial and replay
results used `local-transformers`. The Hugging Face contract tests exercise
the same decision and authority path using simulated router responses. A
successful hosted smoke test would establish token and route access and
conformance for one reply. Qwen route availability, hosted latency, billing
and hosted-model behaviour on governed tool-selection prompts require
separate evidence. [0.5B reply](../reports/qwen-live-evidence.json) · [3B kernel receipt](../reports/qwen3b-kernel-evidence.json) · [3B denial and replay](../reports/qwen3b-denial-evidence.json)
