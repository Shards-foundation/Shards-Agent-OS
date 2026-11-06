# Experimental gVisor sandbox executor (Linux)

This component supplies a **real OS-level workload boundary** for a trusted,
locally running supervisor. It does **not** yet register a new sandbox tool in
the signed Shards-Kernel operator: complete the policy-to-executor integration
before untrusted agents can request execution.

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

## Next integration boundary

The next integration PR must register a narrowly scoped tool in a distinct,
authenticated Shards-Kernel operator process. The operator must independently
check a fresh signed permit bound to **every** ExecutionSpec field before
calling the executor. The agent must never get Docker socket access,
permit-signing credentials, a direct executor RPC or the ability to select
a different isolation backend.

The fingerprint is a binding identifier, **not** an authorisation decision.
Container cleanup cannot undo prior external side effects or guarantee
exactly-once execution.

Unsupported in this increment: general multi-tenant production certification,
bind-mounted repositories, GPU use, outbound networking, Windows/macOS,
an external management API, and automatic retries of unknown effects.
