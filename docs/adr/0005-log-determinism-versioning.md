# ADR 0005: Deterministic replay across versions

Status: Accepted (2026-11-07), implemented (2026-11-09)

## Context
Aeron Cluster recovers by replaying the log into the service. A new version that interprets an old log
entry differently would make replicas diverge or change history.

## Decision
- The service uses only cluster time and the log; no I/O, randomness, wall clock or hash-order
  dependent output.
- SBE schemas only append fields; the schema version increments on each change.
- Behaviour changes are gated by a replicated `ActivateVersion(n)` command: code for version n+1 ships
  first, behaves like n until the command is applied at a log position, then switches on all replicas.
- Snapshots carry the active version.

## Implementation (2026-11-09)
- `StateVersions`: `supported` = what the code knows (`AccountingStateMachine.STATE_VERSION`), `active` = what the
  cluster applies, replicated and in snapshots. `BASELINE = 5` (the first release) applies until a version is
  activated. New rules are written `if (machine.atLeast(n)) new else old`.
- Every member reports `supportedVersion`, `clusterSize` and `hold` with its `MemberLogPosition` (every
  `log.purge.interval`). The report that makes every member support a newer version activates it, unless a member
  sets `cluster.version.hold`; then `admin activate-version --version n` (an `ActivateVersion` entry) activates it,
  refused with `MEMBERS_NOT_READY` or `NOT_NEWER`. Only log content decides, so replays agree.
- A member whose code is older than the active version stops its service with the reason when it meets it (in the
  log or a snapshot) instead of applying entries with old rules; before activation a rollback stays possible.
- Version 6 (2026-11-09, ADR 0023) is the first rule change behind the gate: users and devices of sessions and
  `AuthReservation` for simultaneous use.
- Proven by `StateVersionsTest`, snapshot and log tests, `LocalClusterIT` and the process-based `RollingUpgradeIT`
  (members upgraded one by one, automatic activation on the last, a rolled-back member stops); the newer release is
  simulated with `debug.state.version.supported`.

## Consequences
- Rolling upgrades are possible without a stop-the-world migration.
- Old behaviour must be kept until no log or snapshot older than the switch remains.
- Replay tests (old log → new code → same state) become part of the release checklist.
