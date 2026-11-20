# radiusward-exporter

`radiusward-exporter` runs inside every cluster member and writes the committed accounting log into the configured
sinks, such as PostgreSQL or JSON-lines files. One member at a time holds each sink's lease from the cluster; it
rebuilds the state machine from a snapshot, reads only committed entries, and writes sessions (and optionally events)
in batches, so a sink sees exactly what the cluster decided, even across failover
([ADR 0017](../docs/adr/0017-exporter.md)).

**Stability:** Internal: published as a dependency of `radiusward-embedded` and the radiusward server (through `radiusward-cluster-node`); it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward-cluster-node` runs it, and `radiusward-embedded` and the
radiusward server bring it. To write a sink, implement `radiusward-export-api` and register it as a plug-in
([writing a sink](../docs/sinks/writing-a-sink.md)); the exporter loads it from the class path or `export.plugins.dir`.

## What's inside

| Type | Role |
|---|---|
| `Exporter`, `ExporterContext` | the exporter of one member: one `SinkRunner` thread per configured sink; sink types from `SinkProvider`s on the class path, in `export.plugins.dir`, or given in code |
| `SinkRunner` | standby until the cluster grants this member the sink's lease; then rebuilds the replica, reads the log, writes batches and renews the lease with each new checkpoint; a fenced write, a refused renewal or no renewal for a lease timeout sends it back to standby |
| `LeaseClient` | sends `ExportCheckpoint` through the cluster's ingress and waits for the `ExportCheckpointAck`: the cluster, not the member, decides who holds a lease |
| `StateMachineReplica` | a second copy of the state machine driven by the cluster's own `LogApplier`, from the latest snapshot below the checkpoint: what the cluster decided for every event and what each session looks like afterwards |
| `ClusterLogReader` | reads the member's copy of the log from its local archive, never past the commit position (entries above it may be truncated by an election) |
| `BatchBuilder` | turns the replica's outcomes into batches: applied and stale events, and the latest state of every changed session, including those closed by Accounting-On/Off or the idle timeout |
| `ExportConfig`, `SinkConfig` | `export.sinks`, `export.lease.timeout`, `export.plugins.dir`, `dictionary.dir` and every `sink.<name>.*` key, handed to the plug-in without the prefix |
| `SinkStatus` | what `/state` and `/metrics` show per sink: exporting, epoch, position, lease owner, rows, batches |

**Lease and shutdown.** A runner renews its lease on a second thread, so a sink that hangs on connect or write does not
let the lease expire. On shutdown the runner waits for that thread before closing the lease clients, so no renewal can
connect again behind the member's stopping media driver. The exporter's Aeron clients log their errors: Aeron's
default error handler would exit the member's JVM when the media driver goes away.

## Configuration

Every member gets the same keys:

```properties
export.sinks=pg, archive
export.lease.timeout=10s

sink.pg.type=postgres
sink.pg.url=jdbc:postgresql://db:5432/radius
sink.pg.required=true                 # holds the log; with on.max.lag=block it can stop ACKs
sink.pg.max.lag=4h

sink.archive.type=file
sink.archive.dir=/var/lib/radiusward/export
sink.archive.required=false           # on.max.lag defaults to detach
```

All keys: [docs/configuration.md](../docs/configuration.md#export).

## Requirements

Java 25 and `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`. Runtime dependencies:
`radiusward-cluster-service` (with Aeron Cluster, Apache-2.0) and `radiusward-export-api`.

## Learn more

- [ADR 0017: exporter](../docs/adr/0017-exporter.md), [ADR 0007: sink SPI and lag policy](../docs/adr/0007-sink-spi-lag-policy.md),
  [ADR 0018: storage model](../docs/adr/0018-storage-model.md)
- [Export operations](../docs/operations/export.md), [writing a sink](../docs/sinks/writing-a-sink.md)
- [radiusward-export-api](../export-api/README.md), [radiusward-cluster-service](../cluster-service/README.md),
  [radiusward-cluster-node](../cluster-node/README.md)

## License

Apache-2.0.
