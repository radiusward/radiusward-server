# ADR 0063: Seeding a member whose volume was replaced

Status: Accepted (2026-11-11). Work package 4.6 of [Phase 4](../plans/phase-4.md), first part.

## Context
Members purge their log below the second-latest snapshot ([ADR 0014](0014-log-purge.md)). A member that starts with
an empty volume — a lost disk, a deleted PersistentVolumeClaim, a node replaced — tries to catch up from log position
0, which no other member has any more; on Kubernetes it looped on "failed to join catchup log" and never became
ready ([ADR 0062](0062-members-and-gateways-on-kubernetes.md)). Copying another member's files while it runs is not
consistent, and stopping one to copy them leaves a three-member cluster without a quorum.

## Decision
- A member with an empty data directory (no `cluster/recording.log`) and `cluster.seed.timeout` > 0 first runs Aeron's
  `ClusterBackup` once, with its own media driver and archive, into its own `archive/` and `cluster/` directories,
  from the other members' consensus endpoints. The member's ports are free until it starts, so the backup uses them.
- The copy is kept only when the backup records the live log and the recorded log reaches both the latest snapshot
  it retrieved and the beginning of the current leadership term; then the member starts from it and catches up the
  rest like after a restart. Closing the backup as soon as it reported `BACKING_UP` left the recording megabytes
  short of either on Kubernetes and in the tests, and the member could not join.
- Without a snapshot in the cluster nothing was purged, so the copy is discarded and the member catches up from the
  others' logs. When no member answers within the timeout — a new cluster starting for the first time — the partial
  directories are removed and the member starts empty.
- `/ready` of a member counts a closed election as "leader known": a member started from a snapshot taken after the
  current term began (seeded or restarted) learns the leader's id only from the next term in its log.
- Off by default (`0s`); the Helm chart sets `20s`. The first start of a new cluster then waits that long.

## Consequences
- Replacing a member's volume needs no runbook on Kubernetes: delete the claim and the pod. Measured on kind after a
  purge, under accounting and authentication load: seeded in 4.1 s, ready 10 s after the pod started, same log
  position as the others, no request lost or retransmitted. `ClusterSeedIT` covers a purged log with a leadership
  term after the snapshots, a cluster without snapshots, and no cluster at all.
- Losing two members still loses the quorum: that needs a backup kept outside the cluster (4.6, second part).
