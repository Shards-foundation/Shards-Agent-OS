# First commissioning on Oracle staging

Use this procedure for the installed, disabled staging units and a fresh kernel audit path. It preserves the existing accounts, units, public pins and application installation. None of the commands starts a service. The helper checks Ubuntu 24.04 ARM64, installed package versions, state directory ownership, the systemd definitions and both installed pins before preparing credentials. It refuses an existing ledger. For renewal, retain the audit database and advance the signed revision under a separate change.

## 1. Enroll the installed host in Termius

From the **administrator-controlled** checkout at `/opt/shards-agent-stage/source`, fetch and switch to the exact tested commit from the PR evidence. Check that the working tree is clean before switching. Use the existing venv. Define this shell function for the rest of the Termius session.

```sh
stage() { sudo /opt/shards-agent-stage/venv/bin/python -I /opt/shards-agent-stage/source/deploy/oracle/commission.py "$@"; }
stage enroll
```

The new root-owned 0600 enrollment file contains randomly generated local transport material. Repeating the command returns the same public request. Only the one-line JSON request crosses to the Chromebook. It carries two public pins and two scrypt verifiers. Kernel 0.1.3 requires two distinct enrolled actors. Only `stage-web` receives a usable bearer. The independently generated `stage-reserve` bearer is discarded immediately after deriving its verifier. Both actors are restricted to `echo`.

## 2. Sign the initial policy on the Chromebook

Use the same reviewed source revision in the Linux container and a Python 3.11+ venv with this checkout installed, including its kernel extra. If the checkout is already present, update it to the tested SHA before installing in the local venv. From its root, these commands prepare the local shell. They reuse `~/.shards-authority`.

```sh
python3 -m venv .venv && .venv/bin/python -m pip install '.[kernel]'
commission_script="$PWD/deploy/oracle/commission.py"
commission_python="$PWD/.venv/bin/python"
offline() { "$commission_python" -I "$commission_script" "$@"; }
stage_work=$(mktemp -d "$HOME/shards-stage-commission.XXXXXXXX") && cd "$stage_work"
```

Run the next command. Paste the public enrollment line into its prompt. The helper checks both Oracle pins against the Chromebook's public keys, pins the independent issuer, shows the scope and asks for local confirmation before unlocking the existing policy key.

```sh
offline sign-policy --out operator.json
```

Revision 1 lasts seven days from signature. It names kernel audience `shards-agent-os-oracle-stage`, the private audit path, port 18765, issuer `stage-operator` and key ID `stage-permit-issuer`. Copy the resulting **signed policy JSON** to the next prompt in Termius. Oracle verifies its schema, signature under the already installed public pin, current time, full scope and both local enrollment hashes. The command exclusively installs `operator.json` and `kernel.env` and accepts an identical retry.

```sh
stage install-policy
```

## 3. Provision the origin when the staging credentials exist

An approved staging HTTPS hostname, separate Access audience, TLS-verified private origin and the Worker side of the shared assertion secret are required for hosted acceptance. The origin also needs a scoped Workers AI REST token. Supply existing authorised values only at the local Termius prompts. Secret entry is hidden. The helper writes a root-owned 0600 environment file and checks access to the root-managed bundle directory.

```sh
stage configure-origin
```

An empty bundle directory authorises zero kernel calls. Leave both units stopped until all operational gates are satisfied.

## 4. Approve exactly one staging echo

Defer the following short-lived artifacts until the origin and ingress are ready for a supervised test. The agent authority signs the Access actor's sidecar. The kernel issuer signs its enrolled service actor's permit. The designated human approver signs the exact unsigned permit before the issuer can proceed. Keep the encrypted approval key under that custodian's control. Each workstation/profile needs the four independently authenticated **public** pins in its private `~/.shards-authority` directory. Only the relevant role needs its private key for a given command.

If an independent approver identity has not been designated, pause permit issuance. When explicitly designated, that custodian alone can create its own encrypted keypair using the installed offline key generator. This is the only additional keypair. Retain the existing three.

```sh
"$commission_python" -I -m shards_agent_os.authority_cli keygen --private-key-file "$HOME/.shards-authority/kernel-approver.key.pem" --public-key-file "$HOME/.shards-authority/kernel-approver.pub.hex"
```

Use the private working directory created above. Move only the draft, approval and public pins between custodians over an approved channel. Preserve mode 0600 on draft and approval files. Run each command under its designated role.

| Role | Bounded command |
| --- | --- |
| Draft preparer | `offline draft-echo --out draft.json` |
| Human approver | `offline approve-echo --draft draft.json --reviewer "$(id -un)" --out approval.json` |
| Kernel issuer | `offline issue-echo --draft draft.json --approval approval.json --out permit.json` |
| Agent authority | `read -r -p 'Exact staging Access actor: ' stage_actor && offline bind-echo --actor "$stage_actor" --permit permit.json --out bundle.json` |

The reviewed call is `echo({"text":"oracle-stage-acceptance"})`, once, within ten minutes. The human reads the displayed draft and types its permit ID with the displayed approval phrase. Approval lasts at most five minutes. The issuer verifies the approval, key ID, subject, audience, time and exact call. A separate verifier checks the emitted permit against the pinned issuer. The Agent OS sidecar binds the exact Access actor, arguments and Oracle permit path for five minutes.

In Termius, run the command below and paste the two signed documents into the hidden prompts. The operator can copy each one-line JSON document locally from the Linux container, for example with `wl-copy < permit.json` and then `wl-copy < bundle.json` where clipboard support exists. Clear the clipboard after importing. This transfer needs no ChromeOS shared folder. An existing private SFTP route also works with `--permit FILE --bundle FILE` and mode 0600 uploads. Keep signed grants in private terminals and authorised transfers.

```sh
read -r -p 'Exact staging Access actor: ' stage_actor && stage install-echo --actor "$stage_actor"
```

Oracle verifies both signatures and the service and browser identities before publishing web-owned 0600 artifacts in the root-managed bundle directory. Duplicate or conflicting artifacts cannot replace an earlier grant. No signer, private PEM or passphrase belongs on Oracle.

## Supervised acceptance

After the host administrator confirms the complete staging trust chain, credentials, loopback ports, private TLS ingress and validity windows, start the two staging units together through systemd. Check the listeners, submit the approved echo as the named Access identity and retain its job ID and audit receipt. Check that a second use is refused and compare the receipt after a supervised restart. The ARM64 job exercises the service mechanics with disposable authorities. A real human approval and a hosted browser session each require their own evidence.
