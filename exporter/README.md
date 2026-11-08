# exporter

Runs inside every cluster member ([ADR 0017](../docs/adr/0017-exporter.md)): one `SinkRunner` thread per sink
claims the sink's lease from the cluster (`LeaseClient`), rebuilds the state machine from the snapshot below
the checkpoint (`StateMachineReplica`, the cluster's own `LogApplier`), reads the committed log
(`ClusterLogReader`, never past the commit position), turns outcomes into batches (`BatchBuilder`) and writes
them. Sink types come from the class path and `export.plugins.dir`. Configuration: `ExportConfig`, `SinkConfig`.
