# Export

Committed accounting reaches databases through the exporter inside every cluster member
([ADR 0017](../adr/0017-exporter.md)); the tables are described in [ADR 0018](../adr/0018-storage-model.md).
The Accounting-Response never waits for a database ([accounting contract](../accounting-contract.md)).

## Configure a sink

```properties
export.sinks=pg
sink.pg.type=postgres
sink.pg.url=jdbc:postgresql://db:5432/radius
sink.pg.user=radiusward
sink.pg.password=${env:PG_PASSWORD}
sink.pg.mode=sessions              # or sessions+events
sink.pg.radacct.view=true          # FreeRADIUS-compatible view over accounting_session
```

Every member gets the same configuration; the cluster decides which member exports (lease). All keys:
[configuration.md](../configuration.md#export). Several sinks at once: `export.sinks=pg,archive`, each with its
own cursor, lease and lag.

| Built-in type | Writes |
|---|---|
| `postgres` | `accounting_session` (one row per session), `accounting_event` with `mode=sessions+events`, `radacct` view; PostgreSQL 16+ |
| `radius` | Accounting-Requests to the home servers of proxied realms (`realms`, `servers`, `secret`, `transport` `udp`/`tls` with `tls.*`, `timeout`, `retries`, `strip`; `mode=sessions+events`), Acct-Delay-Time raised; a batch counts once every request is acknowledged ([ADR 0037](../adr/0037-proxying.md)) |
| `file` | JSON lines (`{"type":"event"…}`, `{"type":"session"…}`) in `dir`, rotated at `max.file.size`; on the member holding the lease |

Other targets are plug-ins ([roadmap](../plans/roadmap.md#sinks), [writing a sink](../sinks/writing-a-sink.md)):
put the plug-in and its driver into `export.plugins.dir` (`/opt/radiusward/plugins` in the image).

## PostgreSQL

- **Schema:** created and migrated by the exporter (`schema.manage=auto`). Where the application may not run DDL:
  `radiusward admin export-schema > schema.sql`, apply it, set `schema.manage=validate` (checks the version and
  checksums) or `none`.
- **Sessions:** `accounting_session` holds open and closed sessions; `close_cause` 1 Stop, 2 NAS restart, 3 idle
  timeout (lost Stop; `stopped_at` is then the last event). Closed sessions are kept forever unless
  `sessions.retention` is set (e.g. `400d`). `nas_id` is the NAS entry, `nas_device` the device behind it when the
  entry sets `identity`; `acct_multi_session_id` links the sessions of one client across access points or links
  (roaming, multilink), indexed:
  `SELECT * FROM accounting_session WHERE acct_multi_session_id = $1 ORDER BY started_at`.
- **History** (`mode=sessions+events`): `accounting_event`, daily partitions by commit day, dropped after
  `events.retention` (default `90d`). It costs volume — at 500k sessions roughly 100 GB per day with 5-minute
  interims — so enable it only where you need every Interim.
- **Attributes:** typed columns for the common ones; the rest as JSON (`attributes=json`), raw bytes (`raw`) or
  not at all (`none`). Query JSON with `attributes->'Cisco.AVPair'->>0` (every attribute is an array).
- **Examples:** [deploy/compose/sql/examples.sql](../../deploy/compose/sql/examples.sql).

## Operating

```bash
radiusward admin sinks --members m0,m1,m2              # checkpoint, lag, owner, epoch, detached
curl -s http://member:9090/metrics | grep radiusward_export_
radiusward admin verify-export --jdbc-url … --ack-log acks.csv --nas-id 1001 --members m0,m1,m2
```

| Situation | What happens | What to do |
|---|---|---|
| database down | ACKs continue, lag grows, the log is kept for the sink | fix the database; the backlog drains on its own (alert `RadiuswardExportLagWarning` at 2 h) |
| required sink over `maxLag` | new accounting is not acknowledged (`EXPORT_LAG`), NAS devices retry and buffer | fix the sink; ACKs resume once it is below `maxLag` (alert `RadiuswardExportBlocking`) |
| optional sink over `maxLag` | detached: ACKs continue, the log is no longer held for it | after repair it re-attaches by itself if the log still holds its position; otherwise `admin resync` to the oldest position on disk (`radiusward_log_start_bytes`) and fill the gap from elsewhere |
| exporting member fails | another member takes the lease after the lease timeout (10 s) and continues from the checkpoint | nothing |
| bad rows | written row by row; rows that still fail go to `quarantine` | inspect `quarantine` |
| re-export a range | — | `admin resync --sink pg --position <p>`; sinks are idempotent, nothing is duplicated |

Lag policy per sink: `sink.<name>.required` (default `true`), `max.lag` (default `4h`), `max.lag.bytes`,
`on.max.lag` (`block` for required, `detach` otherwise). Keep `max.lag` below what the disk holds: at the
reference load 4 h is about 60 GB of log per member.
