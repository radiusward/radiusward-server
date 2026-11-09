# Plan: activating state-machine versions (ADR 0005)

Status: implemented (2026-11-09) with automatic activation (option A) — [ADR 0005](../adr/0005-log-determinism-versioning.md),
[upgrade procedure](../operations/release.md#upgrading-a-cluster).

## Problem

Members rebuild their state by replaying the log through the state machine's rules. A release that changes a rule
must not change how entries already in the log are applied, and members on old and new code during a rolling
upgrade must apply every entry alike. ADR 0005 decided a replicated `ActivateVersion`; it does not exist yet, so the
state version moved 2 → 5 by deploying code alone — acceptable only while nothing is released.

## Design

- **Two numbers.** `supported` = the newest behaviour this code knows (`STATE_VERSION`, today 5). `active` = the
  behaviour the cluster applies, **replicated**: kept by the state machine, written in snapshots, changed only by a
  log entry. Rules introduced later are written as `if (machine.atLeast(6)) new else old`; the old branch stays until
  no log or snapshot older than the switch can exist (documented per release).
- **Baseline.** The first release fixes `BASELINE = 5`: a log or snapshot without an activation applies 5.
- **Members report support.** `MemberLogPosition` (already sent by every member every few seconds) gains
  `supportedVersion` and `clusterSize`; the replicated state keeps them per member.
- **Activation entry.** `ActivateVersion(n)` (admin request, or automatic, below) is applied only if every member of
  the cluster has reported `supported ≥ n` and `n > active`; otherwise it is refused with the reason
  (`MEMBERS_NOT_READY`, `NOT_NEWER`). From its log position on, all members apply version n — on every replay.
- **Fail fast.** A member whose code is older than an `active` it meets (in the log or a snapshot) stops with a clear
  error instead of applying entries wrongly; it needs the new release. (Today's snapshot check, generalised.)
- **Visibility.** `/state` and `/metrics`: `radiusward_state_version{kind="active|supported"}` per member;
  `admin state` prints both; a warning while `supported > active` everywhere and activation is held.

## Upgrade procedure

1. Roll the new release through the members one by one (they keep applying `active`).
2. Activation — **your choice**:
   - **A. Automatic (recommended):** once every member reports the new `supported` version, the cluster activates it
     itself (decided by the replicated reports, so deterministic). `cluster.version.hold=true` on any member (it is
     part of its report) holds activation, e.g. to keep a rollback to the previous release possible; then
     `admin activate-version --version n` activates by hand. Like CockroachDB's upgrade finalisation.
   - **B. Manual only:** nothing changes until an operator runs `admin activate-version --version n`.
3. After activation a rollback to code older than `n` is not possible (fail fast above); before it, it is.

## Work items

| # | Item | Size |
|---|---|---|
| 1 | Protocol v5: `ActivateVersion` / `ActivateVersionResult`, `MemberLogPosition.supportedVersion/clusterSize/hold`, `SnapshotHeader.activeVersion`, `StateReport` versions | S |
| 2 | State machine: `active`, `atLeast(v)`, per-member support, activation rules, snapshot, digest, fail fast | M |
| 3 | `MemberReporter` reports; service handles requests and automatic activation (option A) | S |
| 4 | `admin activate-version`, `admin state`; `/state`, `/metrics`, warning | S |
| 5 | Docs: ADR 0005 (implemented), upgrade runbook, protocol, configuration, roadmap | S |

## Tests

- Unit: activation accepted / refused (members missing, not ready, not newer); automatic activation when the last
  member reports; hold; snapshot keeps `active`; replay of a log with an activation gives the same state and digest
  on a machine supporting more; a machine supporting less fails fast; `atLeast` around the activation position (a
  test-only rule gated at version 6 behaves old before and new after).
- Cluster IT (3 members): members report, activation via admin, a member restarted from snapshot keeps `active`.
- e2e: rolling restart of all three processes, activation, digests equal.
