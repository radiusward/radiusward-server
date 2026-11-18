# cluster-service

The deterministic accounting state machine that runs inside Aeron Cluster.

| Class | Role |
|---|---|
| `AccountingService` | `ClusteredService`: decodes commands from the log, applies them, replies over egress, housekeeping timer, snapshots |
| `LogApplier` | the one place that turns log entries into state changes: the service runs it, and the exporter runs a second instance over the committed log ([ADR 0017](../docs/adr/0017-exporter.md)) |
| `AccountingStateMachine`, `Outcomes` | pure dedup rules and per-session progress, one `apply` per event ([ADR 0012](../docs/adr/0012-session-store-dedup.md)); its results |
| `StateVersions` | which rule version the cluster applies, activated once every member supports it ([ADR 0005](../docs/adr/0005-log-determinism-versioning.md)) |
| `SessionStore`, `SessionIdentity` | sessions as primitive columns + open-addressing index, ~77 bytes per session plus the attributes that name a session to its NAS for CoA ([ADR 0036](../docs/adr/0036-coa-and-session-identity.md)) |
| `ExactKeyWindow` | time-bounded exact keys for events without progress values |
| `Reservations` | places held under a simultaneous-use limit until the device's Accounting-Start ([ADR 0023](../docs/adr/0023-simultaneous-use.md)) |
| `ExportState` | per-sink checkpoint, lease, lag and lag policy, changed only by log entries ([ADR 0017](../docs/adr/0017-exporter.md)) |
| `QueryResponder` | read-only questions answered from the state: counters and digest, a session, a user's sessions, pages of sessions |
| `SnapshotCodec` | streams the state into SBE snapshot chunks and back |
| `ServiceStats` | counters published for the management server |

Rules: cluster time only, no I/O, no randomness; allocation-free in steady state (`StateMachineAllocationIT`).
Tests: every rule, a jqwik property (duplicates never change the result), snapshot round trip, replay
determinism, 500k-session footprint.
