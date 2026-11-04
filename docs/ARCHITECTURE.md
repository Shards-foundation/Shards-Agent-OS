# Architecture: two independent trust domains

```
Trusted operator -- reviewed permit approval and issuer (external)
       |                         | signed v2 policy + pinning
       | independently issued    v
       | permit file       Shards-Kernel operator (loopback + SQLite audit)
       |                         ^
       v                         | official MCP stdio relay, enrolled agent bearer
Shards Agent OS daemon ----- shards_kernel mcp-call CLI
       |
       +-- SQLite job state (PENDING -> RUNNING -> SUCCEEDED|DENIED|UNKNOWN)
       +-- SQLite operator HALT latch (new claims only)
       +-- SQLite local memory (typed JSON, TTL, provenance, version)
       +-- Metadata inventory (agents and disabled device capability records)
```

## Control ownership

1. Shards-Kernel authenticates the enrolled actor, cryptographically verifies the independently issued permit, enforces allowlisted tool arguments and records audit intent before tool execution. This project **cannot** grant itself authority to run a tool.
2. Shards Agent OS stores jobs and claims them in `BEGIN IMMEDIATE` transactions. It checks `control.halted` and outstanding `RUNNING` quota in the same transaction as the claim.
3. After claim commit the worker invokes the official `python -m shards_kernel mcp-call` path, with only a minimal environment and the agent bearer. Operator API keys, issuer keys, policy signing keys and unrelated secrets are not propagated.
4. The worker accepts only bounded, typed receipts and records the result. Any timeout, process crash or malformed/ambiguous receipt becomes `UNKNOWN` or remains `RUNNING`. Both are deliberately non-retriable.

## Separation of memory, agent, and devices

Agent directory entries are descriptive, not authenticated identities. Memory namespace strings are partitions, not access-control checks; only trusted local operators can use this interface. Device capability entries remain disabled and never execute code. Until a verified Shards-Kernel interface supports constrained device actions, device access is **out of scope**.

## Interrupt semantics

The OS `halt` latch blocks *future* job claims. The host OS can signal the polling process to shut down, but Shards-Kernel operations already sent to its loopback operator may continue and must be reconciled. A HALTED kernel itself is terminal and is not made active by an Agent OS `resume`.

## Resource model

`--max-running` sets a local outstanding-job capacity. Since crashed `RUNNING` jobs still count, the model chooses safety over liveness. This is not process/cgroup resource isolation, multi-node arbitration or a distributed lock.

## Next architecture gates

Before remote or sensitive device operations: separately reviewed signed policy / tool registration, issuer trust management, capability binding, host sandbox enforcement, externally anchored audit checkpoints, strong workload identities, reproducible restart and adverse-case tests, and operational supervision. Do not unlock these merely by adding an adapter.
