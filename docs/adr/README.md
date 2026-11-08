# Architecture decision records

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-aeron-cluster.md) | Aeron Cluster for replication and consensus | Accepted |
| [0002](0002-ack-boundary.md) | Accounting-Response only after majority commit with fsync | Accepted |
| [0003](0003-event-key-and-dedup.md) | Logical event key and per-session deduplication | Accepted |
| [0004](0004-memory-budget.md) | 1 GiB default memory profile | Accepted |
| [0005](0005-log-determinism-versioning.md) | Deterministic replay across versions | Accepted |
| [0006](0006-nio-udp-transport.md) | Plain NIO `DatagramChannel`, no Netty | Accepted |
| [0007](0007-sink-spi-lag-policy.md) | Pluggable sinks, log-tailing exporter, lag policy | Accepted |
| [0008](0008-dictionaries-licensing-codegen.md) | Bundled CC BY 4.0 FreeRADIUS dictionaries + code generation | Accepted |
| [0009](0009-local-first-development.md) | Local-first development, no Docker in Phase 0–1 | Accepted |

Format: context, decision, consequences. A superseded ADR stays and links to its replacement.
