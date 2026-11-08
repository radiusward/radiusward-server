# export-api

The sink plug-in API ([writing a sink](../docs/sinks/writing-a-sink.md), [ADR 0018](../docs/adr/0018-storage-model.md)):
`AccountingSink`, `SinkProvider` (found with `ServiceLoader`), `Batch`, `ExportEvent`, `SessionSnapshot`,
`SinkContext`, `FencedException`, `StorageMode`, the canonical attribute encoding (`Attributes`) and the SQL
migration runner (`SqlMigrations`). It is the only dependency of a plug-in; keep it storage-agnostic.
