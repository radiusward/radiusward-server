# ADR 0065: A continuous backup outside the cluster

Status: Accepted (2026-11-11). Work package 4.6 of [Phase 4](../plans/phase-4.md), second part; first part
[ADR 0063](0063-seeding-a-replaced-member.md).

## Context
Three members survive the loss of one. A member that loses its volume seeds itself from the other two (ADR 0063).
Losing two members at once — two disks, two nodes, a rack, an operator's mistake — loses the quorum, and with it the
cluster: nothing is left to seed from. Copying a running member's files is not consistent, and the members' own logs
are purged below their snapshots.

## Decision
- **`radiusward cluster-backup`** runs Aeron's `ClusterBackup` continuously, outside the cluster: it fetches the latest
  snapshot (every `backup.interval`) and records the live log from a follower (`backup.source`), into its own data
  directory in a member's layout. It is not a member and takes no part in elections. `/ready` is up while it records
  and holds a snapshot; `/metrics` carries its state, the recorded position and the snapshot's position and time, so
  the distance to the members is what a restore would lose (alerts `RadiuswardBackupNotBackingUp`, `…Behind`,
  `…SnapshotOld`).
- **`radiusward cluster-restore --from <backup> --config <cluster.properties>`** copies a stopped backup into a member's
  empty data directory — never over data — and checks the copy holds a snapshot. After a lost quorum all three
  members are restored from the same backup and started: they hold the same snapshot and log, elect a leader and go on
  from the backup's position.
- It runs the same everywhere: a `backup` StatefulSet with its own volume in the Helm chart (on by default), a
  `backup` profile in compose, `radiusward-backup.service` for systemd. On Kubernetes `scripts/k8s-restore.sh` does
  the whole restore through temporary pods that mount one volume at a time, so node-local volumes work.
- Copies to object storage or another site are file copies of the stopped backup's directory with the operator's
  tools; radiusward gets no storage dependency.

## Consequences
- What a restore loses is bounded by the backup's lag, normally a moment; `ClusterBackupIT` restores a cluster that
  lost every member with every acknowledged event, Docker did the same with the backup volume mounted read-only, and
  the nightly Kubernetes tests run the restore script (`restore-quorum`).
- The backup is one process: while it is down the cluster runs on, and the next start fetches the latest snapshot.
- Aeron opens a recording log for writing even to read it, so a restore checks the snapshot in its copy, not in the
  (possibly read-only) backup.
