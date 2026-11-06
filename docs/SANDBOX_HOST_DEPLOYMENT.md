# Deploy the isolated Linux sandbox broker (controlled-host pilot)

**Scope:** one Linux host, one independently signed operator identity,
one authorised unprivileged agent Linux UID, pinned OCI images and local Unix
socket communications. This is a deployable template, not a deployed service,
a public API, or multi-tenant production certification.

## Trust boundary

~~~text
Independent approver -- Ed25519 signing private key kept OFF the host
    |
    v one-use signed sandbox.exec permit
Unprivileged agent UID (no Docker socket, no audit write)
    |
    v AF_UNIX socket: group access + kernel SO_PEERCRED UID validation
Dedicated trusted operator UID -- StrictKernel / SQLite audit and permit replay
    |
    v host Docker control -- runsc / gVisor restricted workload
~~~

The broker fixes the actor, kernel ID, issuer public verification key and
expected agent UID from trusted host configuration. Client-provided actor,
Docker options, issuer or backend choice are refused. The signed permit must
bind the entire execution specification. A missing or reused permit is denied.

**Important:** rootful Docker socket access is effectively root-equivalent
host privilege. The service user must be trusted; it must remain separate
from the untrusted agent and from the signing key. Use a dedicated Linux host.
Do not assume that this is a remotely exposed or fully multi-tenant sandbox.
Rootless Docker with runsc is a separate deployment variation requiring tests.

## 1. Provision local identities (administrator only)

Assume an existing unprivileged agent user called shards-agent.
Replace this name if your deployed account differs.

~~~bash
sudo groupadd --system shards-broker-clients
sudo useradd --system --home-dir /var/lib/shards-sandbox \
  --shell /usr/sbin/nologin --gid shards-broker-clients shards-sandbox
sudo usermod -aG shards-broker-clients shards-agent

# Root-equivalent privilege for the TRUSTED operator on a dedicated host only
sudo usermod -aG docker shards-sandbox

id -u shards-agent
id -nG shards-agent
id -nG shards-sandbox
~~~

Refuse deployment if the agent belongs to the docker group or can access the
Docker socket, operator process credentials or private audit state.
Group changes may require a new login session.

## 2. Install trusted software and pin configuration

Use a trusted checkout of this private repository. Install the package
with its kernel extra into /opt/shards-agent-os/venv. Verify the published
Shards-Kernel 0.1.3 installation, register the gVisor runsc Docker runtime,
and preload an operator-approved OCI image by immutable SHA-256 digest.

Provision /etc/shards-agent-os/broker.env as a ROOT-OWNED 0600 file:

~~~ini
SHARDS_AGENT_UID=12345
SHARDS_KERNEL_ID=sandbox-local
SHARDS_ACTOR=agent-alpha
SHARDS_ISSUER_ID=independent-approver
SHARDS_KEY_ID=approval-key
SHARDS_ISSUER_PUBLIC_HEX=REPLACE_WITH_VERIFIED_64_CHARACTER_ED25519_PUBLIC_KEY
~~~

The example UID and public key are placeholders. Use the actual numeric
agent UID and verified externally issued Ed25519 public key. Never place
the private signer key on the broker host, in the environment file, or in
the agent account.

Install the [systemd unit template](../deploy/systemd/shards-agent-os-broker.service)
to /etc/systemd/system/shards-agent-os-broker.service after reviewing host
compatibility and the absolute venv path. The service config establishes:

- Operator identity shards-sandbox with no additional Linux capabilities.
- Private 0700 state directory /var/lib/shards-sandbox.
- Group-traversable 0750 runtime directory /run/shards-sandbox.
- Operator-owned 0660 Unix socket broker.sock accessible to the client group.
- Strong systemd filesystem protection, while the trusted operator alone
  remains Docker-authorised.

Once host prerequisites have been verified by an administrator:

~~~bash
sudo systemctl daemon-reload
sudo systemctl enable --now shards-agent-os-broker.service
sudo systemctl status --no-pager shards-agent-os-broker.service
sudo journalctl -u shards-agent-os-broker.service -n 40 --no-pager
~~~

These commands are guidance; no host deployment has been executed here.

## 2A. Automated host preflight and guarded service installation

The repository now includes two executable CLI commands:

- `shards-agent-os-doctor` performs a non-mutating check of Linux,
  Docker/runsc, the separate operator/agent identities, public verifier
  configuration, trusted systemd unit and (with `--running`) the operator
  socket and state directory permissions. Use `--json` for machine-readable
  evidence. No bearer or private key is printed.
- `shards-agent-os-bootstrap` provisions the dedicated client-only group and
  sandbox operator, grants Docker access **only to the trusted operator**,
  copies the packaged immutable systemd unit and, only when explicitly
  requested, starts the service. The default without `--apply` is plan-only.

This bootstrap is intentionally **not** a Docker/runsc installer and does
not generate permit-signing keys or fetch container images. Prepare
`/opt/shards-agent-os/venv` as a **root-owned trusted installation** with
the `shards-agent-os` distribution and `.[kernel]` extra; install Docker
and runsc from trusted sources; pre-create the agent OS account. The parent
directory `/etc/shards-agent-os` must be root-owned `0700`, with the
externally approved **public verifier only** in root-owned
`broker.env` at `0600`. Never put a signing private key here.

Admin-initiated plan and explicit installation:

~~~bash
sudo /opt/shards-agent-os/venv/bin/shards-agent-os-bootstrap \
  --agent-user shards-agent

sudo /opt/shards-agent-os/venv/bin/shards-agent-os-bootstrap \
  --agent-user shards-agent --apply --start \
  --acknowledge-rootful-docker

sudo /opt/shards-agent-os/venv/bin/shards-agent-os-doctor \
  --agent-user shards-agent --running --json
~~~

The command refuses to run as an unprivileged user, to substitute a different
agent UID, to accept a world-accessible verifier configuration, to give the
agent Docker access, to use a package path writable by untrusted accounts,
to start without a registered runsc runtime, or to overwrite a modified
existing service unit. Existing users and groups are reused rather than
duplicated. Before retrying any partially failed bootstrap, inspect the
local service, group memberships and audit paths. Group changes may require
a new agent login.

A dedicated [installed host pilot CI workflow](../.github/workflows/sandbox-host-pilot.yml)
recreates the actual venv and systemd installation on a **disposable Ubuntu
runner**, uses an ephemeral externally controlled issuer, and proves the
agent cannot access Docker or read audit data while a signed gVisor action
succeeds. It then restarts the real service and asserts permit replay denial.
This is independent evidence of reproducible installation, not proof of
deployment to your own permanent host.

## 3. Submit one authorised sandbox operation

A trusted independent approver must first issue a signed v2 one-use permit
for sandbox.exec, the exact image digest, arguments, actor, intended kernel,
expiry and CPU/RAM/PID/time budgets.

Under the agent UID, create two operator-independent, agent-owned 0600 files:
arguments.json with image, argv, timeout_seconds, memory_megabytes,
cpu_millicores, pids_limit; and permit.json holding the signed permit.
The agent cannot sign or alter its permitted scope.

~~~bash
shards-agent-os-sandbox-call \
  --socket /run/shards-sandbox/broker.sock \
  --operator-uid "$(id -u shards-sandbox)" \
  --arguments-file /home/shards-agent/requests/arguments.json \
  --permit-file /home/shards-agent/requests/permit.json
~~~

The client verifies the socket belongs to the pinned operator UID and
does not require any Docker credentials. It submits one bounded request
and never retries an uncertain effect. Exit codes are 0 for authorised,
successful and cleaned workloads, 2 for explicit DENY, or 3 for UNKNOWN
or unsuccessful work. A valid permit is still mandatory even when the
agent has permission to connect to the socket.

## 4. Crash and audit recovery

The broker holds an exclusive audit lock, durably records permit use and
checks the persistent clock. On restart it inspects and removes only its
own labelled orphan containers, reconciling prior incomplete cleanup events
without re-executing them. It also rejects a live competing Unix listener
and removes a stale socket only after checking ownership and absence of an
active listener.

The Linux integration test creates a separate unprivileged agent UID and
socket-only group, proves denied Docker socket access, rejects requests from
the operator UID, executes one real signed gVisor workload from the agent UID,
kills the broker process, and verifies replay denial after restart.

**Limits:** No internet-facing broker, no multi-host accounting, no root-host
compromise protection, no broad shell/network tool catalogue, and no
exactly-once guarantee for external effects. The broker's Docker-capable
service identity is trusted and root-equivalent on a rootful Docker host.
