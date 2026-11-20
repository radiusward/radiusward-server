# radiusward-cluster-node

`radiusward-cluster-node` launches one cluster member: the Aeron media driver, the archive, the consensus module and
the accounting service, with the exporter feeding the sinks, log purge, snapshots and the management endpoints. It also
holds the seeding of a replaced member, the continuous `cluster-backup` process and `cluster-restore`. Operators run it
as `radiusward.jar cluster-node`; `radiusward-embedded` starts members in-process through it.

**Stability:** Internal: published as a dependency of `radiusward-embedded` and the radiusward server; it may change in any release.

## Use it

You normally do not depend on it directly: the radiusward server distribution (`radiusward.jar`, the container image,
the Helm chart) runs it, and `radiusward-embedded` (or `radiusward-junit`) starts a cluster in your tests. Sink
writers implement `radiusward-export-api` and put their jar on the class path or in `export.plugins.dir`.

## What's inside

| Type | Role |
|---|---|
| `ClusterNodeMain`, `ClusterNode`, `ClusterNodeConfig` | `cluster-node`: media driver, archive (fsync per `archive.file.sync.level`), consensus module and the `AccountingService`; the snapshot trigger on the leader (`snapshot.interval`); runs until SIGTERM/SIGINT |
| `ClusterNodeProbes` | what `/health`, `/ready`, `/state` and `/metrics` show: service counters, election state, the last log purge, the exporter; not ready when free disk space falls below `cluster.disk.min.free` |
| `ClusterSeed`, `BackupProcess` | seeding ([ADR 0063](../docs/adr/0063-seeding-a-replaced-member.md)): a member that starts with an empty data directory copies the latest snapshot and the log after it from the others before it joins (`cluster.seed.timeout`); with `cluster.restore.from` it restores itself from a backup when no other member answers |
| `LogPurger`, `LogPurgeConfig`, `MemberReporter` | log purge ([ADR 0014](../docs/adr/0014-log-purge.md)): removes the log below the second-latest snapshot, the slowest required sink checkpoint and the slowest member, in whole archive segments (`log.purge.enabled`); each member reports its own log position |
| `ClusterBackupMain`, `ClusterBackupNode` | `cluster-backup` ([ADR 0065](../docs/adr/0065-cluster-backup.md)): a continuous backup outside the cluster, the latest snapshot every `backup.interval` and the live log, in a member's layout; `/ready`, `/metrics`; it takes no part in elections |
| `ClusterRestore` | `cluster-restore`: copies a stopped backup into a member's empty data directory and checks it holds a snapshot ([docs/operations/backup.md](../docs/operations/backup.md)) |

Every member also runs the [exporter](../exporter/README.md), which tails the committed log into the sinks; the
built-in file, PostgreSQL and RADIUS sinks come with this module.

- **Ports:** member *i* uses `cluster.base.port + 100·i + {0 ingress, 1 consensus, 2 log, 3 catchup, 4 archive, 5 replication}`.
- **Restart after `kill -9`:** Aeron refuses to reuse the directories for 10 s (mark-file liveness); the launcher
  retries for up to 20 s instead of failing.
- **Failover noise:** Aeron events such as "log recording stopped" are logged as one-line warnings.

## Example

```bash
java -jar distribution/target/radiusward.jar cluster-node --config config/local/cluster.properties --config config/local/node-0.properties
java -jar distribution/target/radiusward.jar cluster-backup --config config/local/cluster.properties --config backup.properties
java -jar distribution/target/radiusward.jar cluster-restore --from /var/lib/radiusward-backup --config config/local/cluster.properties --config config/local/node-0.properties
```

Keys: [cluster node](../docs/configuration.md#cluster-node) and [cluster backup](../docs/configuration.md#cluster-backup).
`ThreeNodeClusterIT` runs three real members in one JVM: commit, duplicate, snapshot, leader loss and re-election.

## Requirements

Java 25 and `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`. Runtime dependencies: Aeron Cluster
(Apache-2.0), `radiusward-cluster-service`, `radiusward-exporter`, `radiusward-common` and the built-in sinks (with the
PostgreSQL JDBC driver, BSD-2-Clause). Keep `archive.file.sync.level=2` (the default): below it a power loss can lose acknowledged events.

## Learn more

- [Local cluster](../docs/operations/local-cluster.md), [Kubernetes](../docs/operations/kubernetes.md),
  [backup and restore](../docs/operations/backup.md)
- [ADR 0001: Aeron Cluster](../docs/adr/0001-aeron-cluster.md), [ADR 0014: log purge](../docs/adr/0014-log-purge.md),
  [ADR 0063: seeding a replaced member](../docs/adr/0063-seeding-a-replaced-member.md),
  [ADR 0065: cluster backup](../docs/adr/0065-cluster-backup.md)
- [radiusward-cluster-service](../cluster-service/README.md), [radiusward-exporter](../exporter/README.md),
  [distribution](../distribution/README.md)

## License

Apache-2.0.
