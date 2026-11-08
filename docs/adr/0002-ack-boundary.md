# ADR 0002: Accounting-Response only after majority commit with fsync

Status: Accepted (2026-11-07)

## Context
"Delivered" can mean a local queue hand-off, a successful `offer()`, receipt by a remote driver, a
majority commit, or forced persistence. Only some of these survive failures.

## Decision
The gateway sends the Accounting-Response **only after** the cluster's `AccountingCommitted` egress
message. Archive runs with `aeron.archive.file.sync.level=2` and catalog sync level 2, so commit means
fsynced on a majority. On any failure the gateway stays silent (RADIUS has no Accounting-Reject); the
NAS retries. The contract is "recoverable from the replicated journal", not "written to the database".

## Consequences
- Latency includes one replication round trip plus fsync (milliseconds) — far below NAS timeouts (3–5 s).
- Retries are normal, so deduplication is mandatory (ADR 0003).
- Durability claims must be tested on Linux; macOS `fsync` does not flush the drive cache.
- Full text of the guarantee: [accounting-contract.md](../accounting-contract.md).
