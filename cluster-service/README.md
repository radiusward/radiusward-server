# cluster-service

The deterministic accounting state machine that runs inside Aeron Cluster.

| Class | Role |
|---|---|
| `AccountingService` | `ClusteredService`: decodes commands from the log, applies them, replies over egress, housekeeping timer, snapshots |
| `AccountingStateMachine` | pure dedup rules and per-session progress ([ADR 0012](../docs/adr/0012-session-store-dedup.md)) |
| `SessionStore` | sessions as primitive columns + open-addressing index, ~77 bytes per session |
| `ExactKeyWindow` | time-bounded exact keys for events without progress values |
| `SnapshotCodec` | streams the state into SBE snapshot chunks and back |
| `ServiceStats` | counters published for the management server |

Rules: cluster time only, no I/O, no randomness; allocation-free in steady state (`StateMachineAllocationIT`).
Tests: every rule, a jqwik property (duplicates never change the result), snapshot round trip, replay
determinism, 500k-session footprint.
