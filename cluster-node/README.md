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

Keys: [docs/configuration.md](../docs/configuration.md#cluster-node). `ThreeNodeClusterIT` runs three real
members in one JVM: commit, duplicate, snapshot, leader loss and re-election.
