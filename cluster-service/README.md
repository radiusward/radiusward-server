# radiusward-cluster-service

`radiusward-cluster-service` is the deterministic accounting state machine that runs inside Aeron Cluster on every
member. It applies each committed accounting event once, deduplicating retransmissions per session, keeps the
replicated sessions, simultaneous-use reservations, EAP-AKA sequence numbers and export checkpoints, answers queries
from that state, and writes and restores snapshots. Because every member applies the same log the same way, all
replicas stay identical.

**Stability:** Internal: published as a dependency of `radiusward-embedded` and the radiusward server (through `radiusward-cluster-node` and `radiusward-exporter`); it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward-cluster-node` runs it in every member, and the exporter runs a
second copy of its `LogApplier`; `radiusward-embedded` and the radiusward server bring both. Sink writers receive its
outcomes as events and sessions through `radiusward-export-api`.

## What's inside

| Type | Role |
|---|---|
| `AccountingService` | the `ClusteredService`: decodes commands from the log, applies them, replies over egress, runs the housekeeping timer, takes and loads snapshots |
| `LogApplier` | the one place that turns log entries into state changes: the service runs it, and the exporter runs a second instance over the committed log ([ADR 0017](../docs/adr/0017-exporter.md)) |
| `AccountingStateMachine`, `Outcomes` | pure dedup rules and per-session progress, one `apply` per event ([ADR 0012](../docs/adr/0012-session-store-dedup.md)); reservations and the next SQN per SIM subscriber (state version 8, [ADR 0061](../docs/adr/0061-eap-sim-aka.md)); its results |
| `StateVersions` | which rule version the cluster applies (`BASELINE` 5 up to `STATE_VERSION` 8), activated once every member supports it ([ADR 0005](../docs/adr/0005-log-determinism-versioning.md)) |
| `SessionStore`, `SessionIdentity` | sessions in off-heap records: a 72-byte core record and a 4-byte index slot each, plus a 32-byte member record and 64 bytes of the attributes that name a session to its NAS for CoA once a chunk uses them ([ADR 0036](../docs/adr/0036-coa-and-session-identity.md)) |
| `ExactKeyWindow` | time-bounded exact keys for events without progress values |
| `Reservations` | places held under a simultaneous-use limit until the device's Accounting-Start ([ADR 0023](../docs/adr/0023-simultaneous-use.md)) |
| `ExportState` | per-sink checkpoint, lease, lag and lag policy, changed only by log entries ([ADR 0017](../docs/adr/0017-exporter.md)) |
| `QueryResponder` | read-only questions answered from the state: counters and digest, a session, a user's sessions, pages of sessions |
| `SnapshotCodec`, `ServiceStats` | streams the state into SBE snapshot chunks and back; counters published for the management server |

**Rules.**

- **Determinism:** cluster time only, no I/O, no randomness, no wall clock, no iteration over hash-ordered
  collections that affects output. `DeterminismRulesTest` fails the build on the usual ways to break it.
- **Versioned rule changes:** a change to how an event is applied raises `AccountingStateMachine.STATE_VERSION` and
  keeps the old rule behind `machine.atLeast(n)`; the cluster activates the new version once every member runs it.
- **No allocation in steady state** (`StateMachineAllocationIT`).

Tests: every rule, a jqwik property (duplicates never change the result), snapshot round trip, replay determinism, and
the footprint of 2,000,000 sessions (`StateFootprintIT`).

## Configuration

Set on the cluster node; every member must use the same values:

```properties
service.max.sessions=2000000          # default from the profile
service.tombstone=1h                  # keep stopped sessions to recognise retransmitted Stops
service.idle.timeout=2h               # remove sessions with no event for this long (lost Stop)
service.exact.key.window=15m
service.auth.reservations.max=65536
service.sim.subscribers.max=100000
service.sweep.interval=60s            # housekeeping timer
```

All keys: [docs/configuration.md](../docs/configuration.md#cluster-node).

## Requirements

Java 25 and `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`. Runtime dependencies: Aeron Cluster (Apache-2.0),
`radiusward-protocol`, `radiusward-common`.

## Learn more

- [Accounting contract](../docs/accounting-contract.md) and [architecture](../docs/architecture.md)
- [ADR 0003: event key and dedup](../docs/adr/0003-event-key-and-dedup.md),
  [ADR 0012: session store and dedup](../docs/adr/0012-session-store-dedup.md),
  [ADR 0005: log determinism and versioning](../docs/adr/0005-log-determinism-versioning.md)
- [radiusward-cluster-node](../cluster-node/README.md), [radiusward-exporter](../exporter/README.md),
  [radiusward-protocol](../protocol/README.md)

## License

Apache-2.0.
