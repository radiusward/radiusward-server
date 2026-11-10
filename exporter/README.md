# exporter

Runs inside every cluster member ([ADR 0017](../docs/adr/0017-exporter.md)): one `SinkRunner` thread per sink
claims the sink's lease from the cluster (`LeaseClient`), rebuilds the state machine from the snapshot below
the checkpoint (`StateMachineReplica`, the cluster's own `LogApplier`), reads the committed log
(`ClusterLogReader`, never past the commit position), turns outcomes into batches (`BatchBuilder`) and writes
them. Sink types come from the class path and `export.plugins.dir`. Configuration: `ExportConfig`, `SinkConfig`.

A runner renews its lease on a second thread; on shutdown the runner waits for that thread before closing the lease
clients, so no renewal can connect again behind the member's stopping media driver. The exporter's Aeron clients log
their errors: Aeron's default error handler would exit the member's JVM when the media driver goes away.
