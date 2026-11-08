# ADR 0005: Deterministic replay across versions

Status: Accepted (2026-11-07)

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

## Consequences
- Rolling upgrades are possible without a stop-the-world migration.
- Old behaviour must be kept until no log or snapshot older than the switch remains.
- Replay tests (old log → new code → same state) become part of the release checklist.
