# ADR 0009: Local-first development, no Docker in Phase 0–1

Status: Accepted (2026-11-07)

## Context
The concept (codec, cluster, failover, dedup) should be provable quickly and debuggable in the IDE.
Aeron runs natively on macOS; Postgres is not needed before Phase 3.

## Decision
Phase 0–1 run entirely locally: in-JVM test harness (JUnit), single-process dev mode, and
`scripts/run-local.sh` with separate JVMs on loopback (for the kill -9 failover demo). Phase 1 uses
three local cluster nodes from the start. Docker and compose start in Phase 2, together with Linux
tests for real fsync durability; Testcontainers for Postgres in Phase 3.

## Consequences
- Fast feedback; no container tooling needed to contribute.
- macOS caveats: `fsync` is not power-loss durable (needs `F_FULLFSYNC`), small default UDP socket
  buffers (`kern.ipc.maxsockbuf`), no `/dev/shm` (Aeron uses the temp directory). Durability claims are
  verified on Linux in Phase 2.
- The interop test against FreeRADIUS uses a Homebrew install, also without Docker.
