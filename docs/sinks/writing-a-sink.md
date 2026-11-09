# Writing a sink

A sink is a plug-in that writes exported accounting to one kind of store. The exporter does everything hard —
reading only committed log, deciding outcomes with the cluster's state machine, batching, retries, the lease,
checkpoints, lag — so a sink only has to write a batch durably ([ADR 0017](../adr/0017-exporter.md)).

## The API (`export-api`)

```java
public final class MySinkProvider implements SinkProvider {           // META-INF/services/io.radiusward.export.SinkProvider
    public String type() { return "mystore"; }                          // sink.<name>.type = mystore
    public AccountingSink create() { return new MySink(); }
}

public final class MySink implements AccountingSink {
    public void open(SinkContext context) { … }                         // settings: context.settings() = sink.<name>.*
    public CheckpointStyle checkpointStyle() { return CheckpointStyle.TRANSACTIONAL; }
    public long storedPosition() { … }                                  // -1 if none
    public void write(Batch batch) throws FencedException { … }         // durable when it returns
    public void close() { … }
}
```

A `Batch` holds the log range (`fromPosition`, `toPosition`], the lease `epoch`, the applied events
(`ExportEvent`) and at most one `SessionSnapshot` per session. `SinkContext.attributes()` decodes the raw
attributes: `common(raw)` for typed columns, `json(raw, exclude)` for the canonical JSON.

## The two rules

| | Rule | Why |
|---|---|---|
| events | **insert if absent** by `eventId` | after a crash or a lease handover the last batch can be written again |
| sessions | **update only if newer** by `projectionVersion` | replays and late batches must never move a session back |

Values a session snapshot does not carry (`null`: a closure has no session id or attributes) keep what the store
has; a value it carries replaces the stored one. That includes `startedAt`: the Start's Event-Timestamp, or for a
session first seen by an Interim or Stop that event's time minus its session time, replaced when the late Start
arrives. Events carry the state machine's outcome: `APPLIED`, `STALE` (older than the session's progress) or
`MERGED` (a late Start that only completed the session). The JSON format is defined once (`Attributes.JSON_FORMAT`); store it as-is in the store's best JSON type.

## Checkpoints

- **Transactional:** store `toPosition` and `epoch` with the data in one transaction and refuse the write when a
  newer epoch is stored (`FencedException`). `storedPosition()` returns it; the exporter resumes there.
- **Idempotent replay** (stores without multi-row transactions): write the data, then the checkpoint; after a crash
  the last batch is written again, which the two rules make harmless. Fence the checkpoint row by epoch where the
  store allows a conditional write.

## How common stores map

| Store | Insert if absent | Update only if newer |
|---|---|---|
| PostgreSQL | `ON CONFLICT DO NOTHING` | `ON CONFLICT DO UPDATE … WHERE v < EXCLUDED.v` |
| MySQL / MariaDB | `INSERT IGNORE` | `ON DUPLICATE KEY UPDATE c = IF(VALUES(v) > v, VALUES(c), c)` |
| SQL Server, Oracle, Db2, Firebird | `MERGE … WHEN NOT MATCHED` | `MERGE … WHEN MATCHED AND t.v < s.v` |
| SQLite | `INSERT OR IGNORE` | `ON CONFLICT DO UPDATE … WHERE` |
| Cassandra / ScyllaDB | same primary key = same row | `USING TIMESTAMP <projectionVersion>` |
| DynamoDB | `attribute_not_exists(event_id)` or identical overwrite | `ConditionExpression v < :v` |
| Kafka | key = `eventId`, idempotent producer | compacted topic keyed by session with the version |

## Packaging and licences

Build the plug-in against `export-api` only and put the jar (with its driver) into `export.plugins.dir`. The
radiusward image is Apache-2.0 and bundles a driver only when its licence allows it; drivers under GPL or
proprietary licences (MySQL Connector/J, Oracle, Db2) ship with the plug-in, installed by the operator.

## Testing

Use the file sink (`sinks/file`) and the PostgreSQL sink (`sinks/postgres`, `PostgresSinkTest`) as references:
write every batch twice, write an older epoch after a newer one, write sessions out of order, and kill the
connection mid-batch.
