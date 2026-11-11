# cluster-node

Launches one cluster member: media driver, archive (fsync per `archive.file.sync.level`), consensus module
and the `AccountingService`; schedules snapshots on the leader; serves `/health`, `/ready`, `/state`.

```bash
java -jar distribution/target/radiusward.jar cluster-node --config config/local/cluster.properties --config config/local/node-0.properties
```

- Ports: member *i* uses `cluster.base.port + 100·i + {0 ingress, 1 consensus, 2 log, 3 catchup, 4 archive, 5 replication}`.
- After `kill -9`, Aeron refuses to reuse the directories for 10 s (mark-file liveness); the launcher retries
  for up to 20 s instead of failing.
- Aeron events such as "log recording stopped" during failover are logged as one-line warnings.

- **Seeding** (`ClusterSeed`, [ADR 0063](../docs/adr/0063-seeding-a-replaced-member.md)): a member that starts with an
  empty data directory copies the latest snapshot and log from the others before it joins; with `cluster.restore.from`
  it restores itself from a backup when no other member answers (`cluster.seed.timeout`).
- **Log purge** (`LogPurger`, [ADR 0014](../docs/adr/0014-log-purge.md)): removes the log below what nobody needs any
  more — the latest snapshot, the exporter and the followers (`log.purge.enabled`).
- **Exporter**: every member runs the [exporter](../exporter/README.md), which tails the committed log into the sinks;
  `MemberReporter` publishes the member's role and positions for `/state` and `/metrics`.
- **`cluster-backup`** (`ClusterBackupMain`, `ClusterBackupNode`, [ADR 0065](../docs/adr/0065-cluster-backup.md)): a
  continuous backup outside the cluster — the latest snapshot every `backup.interval` and the live log, into a
  member's layout; `/ready`, `/metrics`.
- **`cluster-restore`** (`ClusterRestore`): copies a stopped backup into a member's empty data directory and checks it
  holds a snapshot ([docs/operations/backup.md](../docs/operations/backup.md)).

```bash
java -jar distribution/target/radiusward.jar cluster-backup --config config/local/cluster.properties --config backup.properties
java -jar distribution/target/radiusward.jar cluster-restore --from /var/lib/radiusward-backup --config config/local/cluster.properties --config config/local/node-0.properties
```

Keys: [docs/configuration.md](../docs/configuration.md#cluster-node) and [cluster backup](../docs/configuration.md#cluster-backup). `ThreeNodeClusterIT` runs three real
members in one JVM: commit, duplicate, snapshot, leader loss and re-election.
