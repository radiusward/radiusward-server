# ADR 0014: Log purge (spike result)

Status: Accepted (2026-11-08) — implementation in Phase 3

## Findings (Aeron 1.54.0)
- Open-source Aeron Cluster never deletes log data; `ClusterTool` has `snapshot` but no purge command.
- The building blocks exist: `AeronArchive.purgeSegments(recordingId, newStartPosition)` (moves the start
  of a recording forward to a segment boundary and deletes the files), `detachSegments` /
  `deleteDetachedSegments`; the cluster's `RecordingLog` (`entries()`, `findLastTermRecordingId()`,
  `getLatestSnapshot(serviceId)`) gives the log recording and snapshot positions.
- Recovery needs the latest snapshot plus the log after it. A lagging or new member catches up by replaying
  the leader's log from its own position; data below that position must still exist, or the member has to
  be seeded from a snapshot (ClusterBackup / `seed-recording-log-from-snapshot`).

## Research (2026-11-08)
- **Commercial option: Aeron Premium "Data Retention Regulator"** — a standalone tool (CLI or programmatic,
  not an in-process agent) "for managing the lifetime of data in Aeron Cluster and Aeron Archive to help
  avoid running out of disk space". Policies include `RetainEnoughDataForRecoveryPolicy` ("keeps the last N
  snapshots and the log following the earliest of these snapshots"), `RetainLengthPolicy`,
  `MatchingRecordingLogPolicy` (applies a policy to the Consensus Module's log recording) and
  `RetainMaxOfPolicy`; it retains everything until `recording.log` is available, supports dry runs and backs
  up segment files before deleting. Binaries come from Adaptive's Artifactory, i.e. it requires an Aeron
  Premium licence and is not usable in an Apache-2.0 distribution.
  Source: <https://aeron.io/premium-docs/aeron-data-retention-regulator/drr-overview.html>.
- **Open-source documentation** describes Archive purging ("deletion of data by segment") and truncation in
  general, with the constraint that "the new start position specified during a purge must be the same as
  the start of a segment"; it gives no cluster-specific procedure.
  Source: <https://aeron.io/docs/aeron-archive/purging-and-truncation/>.
- **Aeron changelog**: 1.47.0 made `purgeSegments` / `deleteDetachedSegments` delete only the newly purged
  range and deletes segment files asynchronously so large purges do not stall the Archive conductor.
  Source: <https://github.com/aeron-io/aeron/wiki/Change-Log>.
- No GitHub issue or discussion was found in which the Aeron maintainers recommend a specific open-source
  procedure for purging the cluster log. Other open-source projects built on Aeron implement exactly the
  pattern below (each member purges its own log below an older snapshot with `purgeSegments`).

## Decision
A `LogPurger` in the cluster-node launcher (Phase 3), run on every member independently after each
snapshot: purge the local log recording below
`min(second-latest snapshot position, slowest required sink checkpoint, slowest follower position)`,
rounded down to the archive segment boundary. Keeping the second-latest snapshot gives one snapshot of
slack if the latest is corrupt. This mirrors the Data Retention Regulator's `RetainEnoughDataForRecoveryPolicy`
(N = 2) and adds what only radiusward knows: the export checkpoints. Operators with an Aeron Premium licence
may run the regulator instead, as long as its policy also retains data above the slowest export checkpoint.

## Consequences
- Phase 1–2: the log grows without bound (~15 GB/h/node at worst-case load); local dev clears `.local/`.
- Phase 3 adds export checkpoints, then purging, with tests for restart and member catch-up after purge.
