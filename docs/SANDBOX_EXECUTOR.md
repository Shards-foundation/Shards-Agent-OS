# Experimental gVisor sandbox executor (Linux)

This component supplies a **real OS-level workload boundary** for a trusted,
locally running supervisor. The experimental local MCP adapter binds
`sandbox.exec` to **Shards-Kernel StrictKernel** with public-only Ed25519
permit verification, but the operator must deploy the server behind an OS
identity boundary that denies untrusted agents Docker socket access. This is
not a remotely authenticated, durable, production-certified service.

## Preconditions

- Linux host with a local Docker daemon accessed only by the trusted supervisor.
- gVisor runsc installed and registered as Docker runtime runsc.
  See the [official gVisor Docker guide](https://gvisor.dev/docs/user_guide/quick_start/docker/).
- An operator-approved OCI image preloaded locally, specified by a complete
  name@sha256 digest. Mutable image tags are refused.
- Never expose the Docker socket to an untrusted agent or workload.
- Never run this component against a daemon controlled by an untrusted tenant.

## First executor increment

- Docker explicitly selects runsc, never falls back to runc.
- No image pulls, external networking, host mounts, shared host IPC,
  inherited agent credentials or privileged containers.
- Non-root user, read-only root filesystem, temporary filesystem, dropped
  capabilities, no-new-privileges, bounded CPU, RAM and process count.
- Output size and wall-clock limits; supervisor attempts forced container
  removal and confirms absence before returning a known outcome.
- Deterministic SHA-256 fingerprint of the full execution specification.
- Real tests check execution, denied filesystem modification, blocked
  external network, output flooding and process termination on timeout.

## Trusted local demonstration

This calls the executor directly from a **trusted host**. It is **not an
authorised agent tool** and does not validate an agent's signed permit.

~~~bash
docker pull busybox:1.36
export SHARDS_SANDBOX_IMAGE="$(docker image inspect --format '{{index .RepoDigests 0}}' busybox:1.36)"
python - <<'PY'
import os
from shards_agent_os.sandbox_executor import ExecutionSpec, GVisorExecutor

request = ExecutionSpec(
    image=os.environ["SHARDS_SANDBOX_IMAGE"],
    argv=("/bin/echo", "sandbox-isolated"),
)
result = GVisorExecutor().run(request)
print(result)
assert result.status == "EXITED" and result.cleanup_confirmed
PY
~~~

A dedicated Linux GitHub workflow installs runsc and exercises the real
runtime on an ephemeral runner. The regular Python unit tests do not provide
evidence of operating-system isolation.

## Signed-permit local MCP bridge

A trusted host can construct an authorised local server with
`shards_agent_os.governed_sandbox.create_governed_sandbox_server(kernel,
actor="agent-alpha")`. The operator supplies a separately booted StrictKernel,
sets an **explicit policy** allowing actor `agent-alpha` and only tool
`sandbox.exec`, and installs an external issuer's **public Ed25519 verifier**.
The private signing key is never available to the executor. This adapter rejects
unconfigured/HMAC-only kernels and any permit with changed/missing execution
parameters. The MCP tool schema requires exactly: image, argv, timeout_seconds,
memory_megabytes, cpu_millicores, and pids_limit.

The authoritative integration proof is the signed, real-process test in the
Linux runsc CI job. A separately signed, one-use v2 permit authorises a real
isolated workload; replay and modified permit parameters do not execute again.
The test issuer is ephemeral, not a production key service. Kernel evidence
is retained in process memory in this example and is not a durable audit store.

### Deployment guard

The MCP server and Docker executor are **trusted components**; do not launch
them as a child of an untrusted agent under the same Docker-enabled OS user.
Operator identity, Unix socket permissions, container lifecycle supervision,
audit persistence/recovery and a non-bypassable deployment perimeter are
required before accepting arbitrary untrusted remote agents.

## Next integration boundary

The next deployment increment must put the already permit-gated local MCP
adapter behind a distinct, authenticated and supervised operator process.
The agent must never get Docker socket access, permit-signing credentials,
a direct executor RPC or the ability to select a different backend.

The fingerprint is a binding identifier, **not** an authorisation decision.
Container cleanup cannot undo prior external side effects or guarantee
exactly-once execution.

Unsupported in this increment: general multi-tenant production certification,
bind-mounted repositories, GPU use, outbound networking, Windows/macOS,
an external management API, and automatic retries of unknown effects.
