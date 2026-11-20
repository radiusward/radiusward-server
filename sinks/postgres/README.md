# radiusward-sink-postgres

A built-in sink that writes the committed accounting into PostgreSQL: one row per session, updated only when newer,
and optionally the history of every event. Reports, billing and the RADIUS server's usage counters and IP pools read
these tables. `radiusward-sink-postgres` is enabled with `sink.<name>.type = postgres`; operators set it up in a
cluster's settings, no code needed.

**Stability:** Internal: published as a dependency of the cluster node (`radiusward-cluster-node`), `radiusward-admin-cli` and through them `radiusward-embedded`; it may change in any release.

## Use it

You normally do not depend on it directly: every cluster member (`radiusward.jar cluster-node`, the image) has it,
and it comes with [`radiusward-embedded`](../../embedded/README.md), where `setting(...)` enables it with the keys
below. In the embedded server keep its own sink first, `setting("export.sinks", "embedded, pg")`: the setting replaces the whole list, and `embedded` is the sink behind `accounting()` and `awaitAccounting(...)`. To write a sink for another database, use [`radiusward-export-api`](../../export-api/README.md).

## What's inside

| Type or table | Role |
|---|---|
| `PostgresSinkProvider` | the `SinkProvider` for `type = postgres`, registered in `META-INF/services` |
| `PostgresSink` | one transaction per batch: `COPY` into staging tables, then `INSERT … ON CONFLICT`, with an epoch-fenced checkpoint ([ADR 0018](../../docs/adr/0018-storage-model.md)) |
| `accounting_session` | one row per session, open and closed; update only if newer (`projection_version`) |
| `accounting_event` | the history with `mode = sessions+events`: insert if absent, daily partitions by commit day, dropped after `events.retention` |
| `radacct` view | the radcheck/radreply schema's `radacct` column names over `accounting_session`, read-only (`radacct.view = true`) |
| `sink_checkpoint`, `quarantine`, `schema_version` | position and epoch per sink; rows that failed on their own; applied migrations with checksums |

One batch, one transaction:

1. lock this sink's row in `sink_checkpoint`; a newer epoch there means another exporter owns the sink: roll back;
2. `COPY` the events and the session snapshots into temporary staging tables;
3. `INSERT … ON CONFLICT DO NOTHING` into `accounting_event`;
4. `INSERT … ON CONFLICT DO UPDATE … WHERE projection_version <` into `accounting_session` (values a closure does
   not know are kept);
5. store position and epoch in `sink_checkpoint`; commit.

A batch with a data error is written again row by row under savepoints; rows that still fail go to `quarantine`.
Every hour the sink creates the partitions of today and the next two days, drops expired ones and removes closed sessions past
`sessions.retention`. The schema is in `src/main/resources/io/radiusward/sink/postgres/migrations` (`V1__init.sql`
to `V4__server_id.sql`); `radiusward admin export-schema` prints it for DBAs.

## Configuration

```properties
export.sinks=pg
sink.pg.type=postgres
sink.pg.url=jdbc:postgresql://db:5432/radius
sink.pg.user=radiusward
sink.pg.password=${env:PG_PASSWORD}
sink.pg.mode=sessions              # or sessions+events
sink.pg.radacct.view=true          # radacct view over accounting_session
```

| Key | Default | Meaning |
|---|---|---|
| `sink.<name>.url` | — (required) | JDBC URL |
| `sink.<name>.user` / `.password` | — | credentials |
| `sink.<name>.mode` | `sessions` | `sessions`, or `sessions+events` for `accounting_event` too |
| `sink.<name>.attributes` | `json` | attributes without a typed column: `json`, `raw` bytes, or `none` |
| `sink.<name>.schema.manage` | `auto` | `auto` (create and migrate), `validate` (check the version and checksums), `none` |
| `sink.<name>.events.retention` | `90d` | event partitions older than this are dropped; `0` keeps all |
| `sink.<name>.sessions.retention` | `0` (keep) | closed sessions older than this are deleted |
| `sink.<name>.radacct.view` | `false` | create the `radacct` view (not with `schema.manage = none`) |
| `sink.<name>.connect.timeout.seconds` / `.socket.timeout.seconds` | `5` / `120` | JDBC connect and socket timeouts |

The general sink keys (`required`, `max.lag`, `on.max.lag`, `batch.rows`, …) are in
[configuration.md](../../docs/configuration.md#export). Query attributes stored as JSON with
`attributes->'<Attribute-Name>'->>0` (every attribute is an array); more in
[examples.sql](../../deploy/compose/sql/examples.sql).

## Requirements

- Java 25; PostgreSQL 16 or newer.
- PostgreSQL JDBC driver (pgjdbc, BSD-2-Clause), and `radiusward-export-api`.
- Tests: `PostgresSinkTest` uses Testcontainers; it is skipped without Docker and required in CI.

## Learn more

- [Export](../../docs/operations/export.md): schema management, retention, operating, failure cases
- [ADR 0018: storage model](../../docs/adr/0018-storage-model.md), [ADR 0017: exporter](../../docs/adr/0017-exporter.md),
  [ADR 0007: sink SPI and lag policy](../../docs/adr/0007-sink-spi-lag-policy.md)
- [Writing a sink](../../docs/sinks/writing-a-sink.md)
- [`radiusward-export-api`](../../export-api/README.md), [`radiusward-sink-file`](../file/README.md),
  [`radiusward-admin-cli`](../../tools/admin-cli/README.md)

## License

Apache-2.0.
