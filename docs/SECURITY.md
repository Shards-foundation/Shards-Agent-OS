# Security boundaries / threat model

**Trust:** local POSIX operator shell and filesystem, kernel's separate signer and independent signed-policy operator. The Agent OS process must have **only an enrolled agent bearer**; it may not possess policy, permit-signing or operator-administration secrets. The local database is not an access-control server and cannot defend against the host root user.

**Prevented or reduced:** duplicate concurrent claims by SQLite transactions; unauthorized kernel operations by the independent signed-permit boundary; immediate replay after worker uncertainty by never retrying `RUNNING`/`UNKNOWN`; local over-dispatch through capacity and HALT latch; exposure of permit paths in job listing; direct execution of registered devices and tools through metadata.

**Not prevented:** malicious host administrator, compromised operator/signer, physical device access outside the broker, tool invocations that bypass the kernel boundary, credentials accidentally supplied to applications or shell environments, host-level memory access, tampering with an entire SQLite directory, replay across independently deployed replicas, or side effects already committed before CLI timeout. Local memory is stored as plaintext and is not suitable for secrets without additional encryption and access-control infrastructure.

**Permissions:** the state SQLite file is created with 0600 and final-component O_NOFOLLOW under POSIX. Place its parent directory under a private 0700 directory with trusted ownership; this reduces path replacement risk. The check does not prove resistance against a malicious host administrator. Kernel operator state must remain on the operator's independent protected path. Do not share credentials across agents.

**Release standard:** passing unit tests is not sufficient for live sensitive operations. Verify signed real-process MCP ALLOW, exact parameter binding and replay DENY, crash/recovery, negative auth, timeouts, audit integrity and host permissions. Production deployment is not claimed.
