# radiusward-sink-file

A built-in sink that writes the committed accounting as JSON lines into a directory: an archive that needs no
database, and the reference implementation for people writing a sink of their own. `radiusward-sink-file` is
enabled with `sink.<name>.type = file`; operators set it up in a cluster's settings, no code needed.

**Stability:** Internal: published as a dependency of the cluster node (`radiusward-cluster-node`) and through it `radiusward-embedded`; it may change in any release.

## Use it

You normally do not depend on it directly: every cluster member (`radiusward.jar cluster-node`, the image) has it,
and it comes with [`radiusward-embedded`](../../embedded/README.md), where `setting(...)` enables it with the keys
below. In the embedded server keep its own sink first, `setting("export.sinks", "embedded, archive")`: the setting replaces the whole list, and `embedded` is the sink behind `accounting()` and `awaitAccounting(...)`. To write a sink of your own, use [`radiusward-export-api`](../../export-api/README.md) and read this module's
two classes as an example.

## What's inside

| Type | Role |
|---|---|
| `FileSinkProvider` | the `SinkProvider` for `type = file`, registered in `META-INF/services` |
| `FileSink` | writes `{"type":"event",…}` and `{"type":"session",…}` lines to `<dir>/<sink>-m<member>-<position>.jsonl`, rotated at `max.file.size` |

- **Transactional per member** (`CheckpointStyle.TRANSACTIONAL`): after the data is fsynced, `<sink>.position`
  records position, epoch, file and length (written to a temporary file, fsynced, renamed). On open the active file is
  cut back to the recorded length, so a batch is either completely in the file or not at all.
- **Fenced:** a batch with an older epoch than the stored one is refused.
- **Where the files land:** on whichever member holds the sink's lease. After the lease moves, the new member's files
  may repeat the last batches of the old one; consumers deduplicate by `event_id` and keep the session with the
  highest `version`.
- **Events** are written only with `mode = sessions+events`; sessions always.

## Configuration

```properties
export.sinks = archive
sink.archive.type = file
sink.archive.dir = /var/lib/radiusward/archive
sink.archive.mode = sessions+events      # default: sessions
sink.archive.max.file.size = 256m
```

| Key | Default | Meaning |
|---|---|---|
| `sink.<name>.dir` | — (required) | directory of the files; created if missing |
| `sink.<name>.mode` | `sessions` | `sessions` or `sessions+events` (also an event line per accounting event) |
| `sink.<name>.max.file.size` | `256m` | size at which a new file is started |

The general sink keys (`required`, `max.lag`, `on.max.lag`, `batch.rows`, …) are in
[configuration.md](../../docs/configuration.md#export).

## Requirements

Java 25. Depends only on `radiusward-export-api`.

## Learn more

- [Export](../../docs/operations/export.md)
- [Writing a sink](../../docs/sinks/writing-a-sink.md)
- [ADR 0007: sink SPI and lag policy](../../docs/adr/0007-sink-spi-lag-policy.md), [ADR 0017: exporter](../../docs/adr/0017-exporter.md)
- [`radiusward-export-api`](../../export-api/README.md), [`radiusward-sink-postgres`](../postgres/README.md),
  [`radiusward-sink-radius`](../radius/README.md)

## License

Apache-2.0.
