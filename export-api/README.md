# radiusward-export-api

The interfaces for sending radiusward's committed accounting to your own store: a billing system, a data warehouse,
a message queue. A sink gets batches of applied events and session snapshots in commit order, with the same contract
whether it runs as a plug-in in a cluster or in a test with [radiusward-embedded](../embedded/README.md).
`radiusward-export-api` is the only dependency a sink needs; the exporter does the hard parts (reading only
committed log, batching, retries, the lease, checkpoints, lag).

**Stability:** Public API: kept compatible within a minor version (until 1.0, a minor version may change it, with a
note in the release).

## Use it

```xml
<dependency>
    <groupId>io.radiusward</groupId>
    <artifactId>radiusward-export-api</artifactId>
    <!-- version from radiusward-bom; see the main README -->
    <scope>provided</scope> <!-- for a plug-in jar: the member brings it; for tests, test scope -->
</dependency>
```

Gradle: `compileOnly("io.radiusward:radiusward-export-api")` for a plug-in (version from the BOM platform).

## What's inside

| Type | Role |
|---|---|
| `AccountingSink` | `open`, `checkpointStyle`, `storedPosition` (-1 if none), `write(Batch)` (durable when it returns), `close`; `AccountingSink.of(batch -> ...)` makes one from a function for tests |
| `SinkProvider` | `type()` (what `sink.<name>.type` names) and `create()`; `SinkProvider.of(type, factory)` makes one in code |
| `Batch` | the log range (`fromPosition`, `toPosition`], the lease `epoch`, the applied events and at most one snapshot per session |
| `ExportEvent`, `SessionSnapshot` | an accounting event with its outcome, keys and raw attributes; a session's state with its `projectionVersion` |
| `SinkContext` | the sink's name, the member, its `sink.<name>.*` settings, the storage mode, and `attributes()` to decode raw attributes |
| `Attributes` | `common(raw)` for typed columns, `json(raw, exclude)` for the canonical attribute JSON |
| `FencedException` | thrown by `write` when an exporter with a newer epoch has already written: this one steps back |
| `StorageMode` | `sessions` or `sessions+events` |
| `SqlMigrations` | versioned SQL migrations for sinks that own a schema (`apply`, or `script` for a DBA) |

Two rules make a sink correct under replays and lease handovers: **insert events if absent** by `eventId`, and
**update sessions only if newer** by `projectionVersion` ([writing a sink](../docs/sinks/writing-a-sink.md)).

## Example

```java
public final class BillingSink implements AccountingSink {
    private Billing billing;

    @Override
    public void open(SinkContext context) {
        billing = Billing.connect(context.setting("url", "http://localhost:8080"));
    }

    @Override
    public CheckpointStyle checkpointStyle() {
        return CheckpointStyle.IDEMPOTENT_REPLAY;     // the position after the data: the last batch may come again
    }

    @Override
    public long storedPosition() {
        return billing.position();                    // -1 the first time
    }

    @Override
    public void write(Batch batch) {
        batch.sessions().forEach(billing::upsertIfNewer);
        billing.storePosition(batch.toPosition());
    }

    @Override
    public void close() {
        billing.close();
    }
}
```

In a cluster: a `SinkProvider` in `META-INF/services/io.radiusward.export.SinkProvider`, the jar on the class path or
in `export.plugins.dir`, and `export.sinks` lists the sink. In a test:
`EmbeddedRadiusward.builder().sink(new BillingSink())`.

## Requirements

Java 25. Depends on `radiusward-units`, `radiusward-codec` and `radiusward-dictionaries` (for decoding attributes).

## Learn more

- [Writing a sink](../docs/sinks/writing-a-sink.md): the contract, checkpoints, how common stores map
- [ADR 0017: the exporter](../docs/adr/0017-exporter.md), [ADR 0018: the storage model](../docs/adr/0018-storage-model.md)
- The built-in sinks as examples: [file](../sinks/file/README.md), [PostgreSQL](../sinks/postgres/README.md)

## License

Apache-2.0.
