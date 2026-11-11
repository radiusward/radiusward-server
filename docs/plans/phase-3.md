# Phase 3 build plan: export to PostgreSQL, sink plug-ins, log purge, metrics

Status: **done** (2026-11-08) · Created: 2026-11-08 · Revised: 2026-11-08 (session-first storage,
reducer in the exporter) · Report: [below](#phase-3-report) · Builds on: [Phase 2](phase-2.md) · Sink roadmap: [roadmap.md § Sinks](roadmap.md#sinks)

## Goal

Committed accounting reaches PostgreSQL, fed asynchronously from the replicated log, as reconciled
**sessions** (like FreeRADIUS `radacct`) and, if enabled, as immutable **event history**. The log on disk stops
growing because it is purged, and operators see export lag and health in Prometheus. The plug-in API carries
already reconciled data, so MySQL, SQL Server, Oracle, Db2, Firebird, SQLite, Kafka, Cassandra and DynamoDB
can be added later without RADIUS logic in any sink.

**The ACK boundary does not change** (confirmed 2026-11-08): an Accounting-Response is sent once the record
is committed to the replicated log (fsynced on a majority), never after the database write. While the database
is down the log on disk is the buffer. The only effect a sink can have on ACKs is the lag policy: a `required`
sink more than `maxLag` behind stops new ACKs (`block`).

## Exit criteria

1. **Sessions correct:** after any load, every session in `accounting_session` equals the cluster's replicated
   session (`admin verify-export`), including out-of-order Interims, Stop before a delayed Interim and
   Accounting-On/Off.
2. **History exactly once** (mode `sessions+events`): every applied event once in `accounting_event`;
   duplicates never exported.
3. **Outage:** database down for 30 min under load → ACKs continue, the backlog drains, no loss, no duplicates.
4. **Crash and handover:** exporter or exporting member killed mid-batch, and a lease handover with the old
   exporter still alive → no gap, no duplicate, the stale exporter's writes are fenced off.
5. **Lag policy:** a `required` sink over `maxLag` stops ACKs and resumes them after catching up; an optional
   sink detaches while the others continue.
6. **Disk bounded:** the log on disk is about two snapshot intervals in steady state; restart and follower
   catch-up after a purge work.
7. **Throughput:** session upserts and event inserts keep up with the reference load (8.3k events/s average at
   1-min interims, more in bursts) with headroom; catch-up after an outage is faster than intake. Numbers
   measured, defaults chosen from them.
8. **Memory:** a small member with the exporter (including its state-machine replica) stays within 1 GiB at
   2M sessions.
9. **Metrics:** `/metrics` (Prometheus text): lag per sink (bytes, seconds), rows, batch latency, errors,
   lease owner and epoch, quarantined records, plus the existing node and gateway counters.
10. **Docs:** ADRs, export operations guide, sink plug-in guide, configuration, failure matrix.

## Confirmed decisions (2026-11-08)

| # | Decision |
|---|---|
| 1 | ACK at log commit, never after the sink write (unchanged contract) |
| 2 | Exporter runs **inside each cluster member** as its own agent thread; one member exports per sink, chosen by a **lease in the replicated state** (cluster time, renewed by checkpoints, default timeout 10 s, an **epoch** incremented on every handover). It reads the local archive and never passes the member's commit position. Built so it can later run as a sidecar container (Phase 4) |
| 3 | **The exporter is the reducer:** it runs the **same `AccountingStateMachine` code** while reading the log, starting from the latest cluster snapshot below its checkpoint, and exports only what the cluster **applied**: applied events (duplicates never; stale events only to history, flagged) and the reconciled **session snapshot** after each change, with `projection_version` = log position. Sinks contain no RADIUS logic. Alternative checked in the P3.1 spike: the service writes small outcome records into the log (Aeron service `offer`) — less exporter memory, more log volume; the spike decides |
| 4 | **Storage modes:** `sessions` (**default**; `accounting_session`, one row per session like FreeRADIUS `radacct`), `sessions+events` (plus immutable `accounting_event` history, opt-in with its own retention), raw archive (opt-in: `attributes=raw` or the file sink). Optional **`radacct`-compatible view** for existing FreeRADIUS reports and tools |
| 5 | **Database retention:** closed sessions kept forever by default (`sessions.retention` to limit); event history only when enabled, with `events.retention` (suggested 90 days). The **cluster log** is separate: bounded by the `LogPurger` (≈ 1–2 h steady state, at most `maxLag` during a sink outage) |
| 6 | Schema migrations by a **small versioned SQL runner of our own** in `export-api`, no Flyway/Liquibase: plain SQL files with Flyway-style names (`V1__init.sql`), applied in order in a transaction, checksums in a `schema_version` table, only by the lease holder under a database lock (`pg_advisory_lock` and equivalents). Each sink plug-in ships its own SQL per dialect. **`schema.manage=auto\|validate\|none`** and **`radiusward admin export-schema --sink <name>`** prints the full SQL for DBAs. Same file names keep a later switch to Flyway cheap |
| 7 | Second built-in sink: **JSON lines file**; proves several sinks at once, reference for plug-in authors, doubles as raw archive |
| 8 | PostgreSQL tests with **Testcontainers, skipped in `./mvnw verify` when Docker is missing**; Docker stays optional for development. **In CI a skip is a failure:** the workflows pass `-Dradiusward.require.docker=true`, which turns "Docker not available" into a failing test instead of a skip, so the PostgreSQL tests can never silently not run on GitHub (Linux runners have Docker) |
| 9 | **`/metrics` in Prometheus text format** on the management port of every member and gateway, written from the existing stats counters (no client library, nothing computed per packet). OpenTelemetry users scrape it with an OTel Collector. Example alert rules shipped; optional compose profile `monitoring` with Prometheus + Grafana and one dashboard |
| 10 | PostgreSQL defaults: **`required=true`, `maxLag=4h`, `onMaxLag=block`** (4 h ≈ 60 GB of log at the reference load, within a 100 GB volume) |
| 11 | **PostgreSQL 16+**, tested on 17 (`postgres:17-alpine`) |
| 12 | New runtime dependency **pgjdbc** (BSD-2-Clause) |
| 13 | **PostgreSQL in compose by default**, so `docker compose up` gives a working export |
| 14 | The plug-in API (`export-api`) stays **storage-agnostic and versioned**; drivers are bundled only when their licence fits Apache-2.0, other sinks ship as plug-ins for `plugins/` ([roadmap](roadmap.md#sinks)) |
| 15 | **Two primitives every sink implements:** event *insert-if-absent* by `event_id`, session *update-only-if-newer* by `projection_version`; and one of two **checkpoint styles**: *transactional* (checkpoint row in the same transaction as the data, fenced by the lease epoch — relational databases, Kafka transactions) or *idempotent replay* (checkpoint after the write, epoch-fenced checkpoint row — Cassandra, DynamoDB) |
| 16 | **Stable identities:** `event_id` = 128-bit exact key (UUID); `session_key` = 128-bit session key; partition day = **commit day from the cluster timestamp in the log** (identical on every replay); source event time in its own column |
| 17 | **Attribute encoding** (canonical, defined once in `export-api`): typed columns for queried values; the rest as residual JSON where **every attribute is an array**, binary values explicitly encoded (base64), unknown attributes by numeric vendor/type, a format version column, never `\u0000` in strings. Column type per dialect (`jsonb`, `JSON`, text/BLOB); `attributes=json\|raw\|none` |
| 18 | **Counters** as signed 64-bit (`bigint`); values beyond that are flagged in `quality_flags`, never truncated silently. Missing values are `NULL`, never 0 |
| 19 | **Bulk path stays binary `COPY`** for both tables: events and reduced session snapshots are copied into per-connection staging tables, then merged with `INSERT … SELECT … ON CONFLICT` (events: `DO NOTHING`; sessions: `DO UPDATE … WHERE version is newer`). Multi-row `INSERT` only where measured faster (small batches) |

## Design

```text
gateway ─▶ cluster log (fsync, majority) ─▶ ACK
                │
     member holding the lease (epoch e) for sink S:
                └─▶ exporter agent
                      ├─ local archive replay ≤ commit position, from snapshot below checkpoint
                      ├─ AccountingStateMachine replica  → outcome per event, reconciled session
                      ├─ batch (rows / linger), at most one session row per key
                      ├─▶ sink.write(events, sessions, checkpoint(e))   one transaction where possible
                      └─▶ ExportCheckpoint(S, position, member, epoch, lastEventTime) ─▶ cluster
```

- **Reading:** Archive replay of the local log recording, bounded by the member's commit-position counter, so
  entries an election could truncate are never exported. The decoder for Aeron's log framing (session
  messages, timers, session open/close, leadership terms) sits behind one class, pinned by a test against
  Aeron 1.54. Cluster timers are part of the log, so the replica's sweeps match the cluster's.
- **Replica:** loads the cluster snapshot (our own `SnapshotCodec`) below the checkpoint, replays silently up
  to the checkpoint, then exports. Memory ≈ 77 bytes per session.
- **Checkpoints, lease, epoch:** new message `ExportCheckpoint(sinkId, position, memberId, epoch,
  lastEventTime)`; the state machine keeps per sink: checkpoint, lease owner, expiry, epoch, detached flag;
  in snapshots → protocol and snapshot format version 2 (ADR 0005). Lag in bytes and time is deterministic.
  The sink's own checkpoint (in the database) is the resume point; the cluster checkpoint drives lag and
  purge and may trail it, which is safe.
- **Lag policy:** `block` → `AccountingRejected(EXPORT_LAG)` (new reason), the gateway stays silent;
  `detach` → the sink stops holding the purge, alert, manual `resync`.
- **Sink SPI** (`export-api`): `AccountingSink` with `open(SinkContext)`, `write(Batch)`, `close`, `health`,
  `checkpointStyle()`; found with `ServiceLoader` on the class path and in `plugins/*.jar`. A batch holds
  applied events and session snapshots as zero-copy views; attributes available as a typed list
  `(name, type, value)`, as canonical JSON and as raw bytes. One thread per sink, bounded memory, retry with
  backoff, all exceptions contained. Records a sink cannot write go to **quarantine** (table or file), never
  silently skipped.
- **PostgreSQL sink**, one transaction per batch:
  1. binary `COPY` of the batch's events and of its reduced session snapshots into per-connection unlogged
     staging tables;
  2. `INSERT INTO accounting_event SELECT … FROM staging ON CONFLICT DO NOTHING` (mode `sessions+events`);
  3. `INSERT INTO accounting_session SELECT … FROM staging_sessions ON CONFLICT (session_key) DO UPDATE …
     WHERE accounting_session.projection_version < EXCLUDED.projection_version`;
  4. `UPDATE sink_checkpoint SET position = ?, epoch = ? WHERE sink = ? AND epoch <= ?` — no row → a newer
     exporter owns the sink → roll back;
  5. commit.
  Multi-row `INSERT` as fallback for small batches (measured, not assumed).
- **Schema (starting point, benchmarked):**
  - `accounting_session` — `session_key` (PK), `nas_id`, `acct_session_id`, `user_name`,
    `calling_station_id`, `framed_ip`, `nas_ip`, `started_at`, `last_received_at`, `stopped_at`,
    `session_seconds`, `input_octets`, `output_octets`, `state`, `terminate_cause`, `quality_flags`,
    `projection_version`; `fillfactor` 80 as a benchmark start; **no indexes on columns that change on every
    Interim** (so updates can stay HOT; HOT still writes a new row version, it only skips new index
    entries); partial index for active sessions (`WHERE stopped_at IS NULL`); no changing JSON in this table.
  - `accounting_event` (opt-in) — `commit_day` + `event_id` (PK), `log_position`, `received_at`
    (commit time), `source_event_at`, `nas_id`, `gateway_id`, `session_key` (nullable for
    Accounting-On/Off), `status_type`, `outcome` (applied / stale), `session_seconds`, octets, `framed_ip`,
    `quality_flags`, `attribute_format`, `attributes` (residual JSON); range-partitioned by `commit_day`;
    B-tree on `(session_key, received_at)`, BRIN on `received_at`; no GIN by default.
  - `sink_checkpoint`, `schema_version`, `quarantine`.
  - Optional view `radacct` mapping `accounting_session` to FreeRADIUS column names.
- **Housekeeping:** partitions created ahead; expired ones `DETACH PARTITION … CONCURRENTLY`, then dropped
  (partitions still need vacuum and statistics); closed sessions removed per `sessions.retention`.
- **File sink:** JSON lines (canonical encoding), rotated by size or time, file names by log position range.
- **LogPurger** (ADR 0014): after each snapshot every member purges its own log recording below
  `min(second-latest snapshot, slowest required checkpoint, slowest follower)`, rounded down to the segment
  boundary; dry-run mode; detached sinks no longer hold it.

## New modules

| Module | Purpose |
|---|---|
| `export-api` | sink SPI, batch/record views, canonical attribute encoding, migration runner, `SinkContext`; versioned — the only dependency of a plug-in |
| `exporter` | log tailing bounded by the commit position, state-machine replica, lease and epoch, batching, retry, checkpoints, lag, quarantine, plug-in loading |
| `sinks/postgres` | PostgreSQL sink, SQL migrations, partition and retention housekeeping, `radacct` view |
| `sinks/file` | JSON-lines sink |

## Work steps

### P3.1: Spike — reading the log and the reducer (size S)

- Replay the local log recording up to the commit position; decode Aeron's framing and `AccountingCommand`;
  across leadership terms, elections, restarts; decode speed.
- Replica from a snapshot + replay gives the cluster's outcomes and digest; compare with service-written
  outcome records (Aeron service `offer`): memory, log volume, complexity.
- ✅ **Done when:** 1M committed events read in order, never past the commit position during an election; the
  replica's digest equals the cluster's; decision 3's variant chosen and recorded.
- **Result (2026-11-08, `LogReplicaSpikeIT`):** on all three members the replica (shared `LogApplier`) ends on
  the cluster's digest, from the latest snapshot and from position 0, across a leader failover; a reader
  tailing a follower live through the failover never passed the commit position. Replay + apply runs at
  0.9–3.6 M commands/s (80k events tested; 1M left to `ExportThroughputIT`). Finding: an election stops and
  later extends the log recording, which ends a following replay — the reader restarts the replay from its
  position (`ClusterLogReader.reopens`). The log stayed one recording across terms. **Decision 3: replica
  variant chosen**; service-written outcome records are not needed.

### P3.2: Checkpoints, lease, epoch, lag in the replicated state (size M)

- `ExportCheckpoint`, lease with epoch, `EXPORT_LAG`, detach flag; snapshot v2; `block`.
- ✅ **Done when:** deterministic unit and replay tests, v1 snapshots still load, `ThreeNodeClusterIT` covers a
  lease takeover with a new epoch.
- **Result (2026-11-08):** protocol and snapshot format version 2 (`ExportCheckpoint`, `ExportCheckpointAck`,
  `SinkChunk`, `RejectReason.EXPORT_LAG`); `ExportState` in the state machine, applied by the shared
  `LogApplier`. Lag by time counts from the first entry a sink had not exported after it was last caught up, so
  idle periods never count (`ExportStateTest.idleTimeIsNotLag`). `ThreeNodeClusterIT`: claim → epoch 1, refusal
  while valid, takeover after expiry → epoch 2, a required sink over its limit rejects accounting with
  `EXPORT_LAG` until it checkpoints. Note for upgrades: members must all run schema 2 before an exporter is
  enabled (an older member would ignore checkpoints and decide differently); recorded for ADR 0017.

### P3.3: Exporter core, export API, file sink (size L)

- `export-api` (SPI, views, canonical encoding, migration runner), `exporter` (replica, batching, both
  checkpoint styles, quarantine), `sinks/file`; plug-in loading from `plugins/`; a test plug-in.
- ✅ **Done when:** two sinks run at once from the same log with independent cursors; killing the exporter
  thread or the member resumes without gap or duplicate; the encoding round-trips repeated, binary and
  unknown attributes.
- **Result (2026-11-08):** modules `export-api` (SPI, `Batch`, `ExportEvent`, `SessionSnapshot`, canonical
  `Attributes`), `exporter` (`ClusterLogReader`, `StateMachineReplica`, `BatchBuilder`, `LeaseClient`,
  `SinkRunner`, plug-in loading), `sinks/file`; the state machine reports sessions closed without an event of
  their own (Accounting-On/Off, idle timeout) so they are exported too. `ExporterIT` (3 members, two file
  sinks, 2k req/s, exporting member stopped): lease moves within ~2 s, all ~26k applied events exported once,
  0 duplicate lines across members, all 2,000 sessions equal the replicated state; 3 of 3 repeat runs green.
  Found: the lease client busy-spun while waiting for acks; it now parks. (A run that lost 256 requests at the
  time was not caused by it — see P3.5.) Deviation: batches hold copies (records), not zero-copy views —
  bounded by `batch.rows`, simpler for plug-ins. The migration runner moves to P3.4 with its first user.

### P3.4: PostgreSQL sink (size L)

- Transaction above, schema and migrations (`schema.manage`, lock against concurrent members), partitions,
  retention, `radacct` view; Testcontainers tests (skipped locally without Docker; fail in CI via
  `-Dradiusward.require.docker=true` in `ci.yml`).
- ✅ **Done when:** every batch written twice → same rows; crash between `COPY` and commit; a fenced stale
  exporter cannot write; three members starting at once migrate once; `validate` refuses a schema that is
  behind or has a changed checksum; `none` never runs DDL; benchmark matrix below measured.

| Variant | Purpose |
|---|---|
| sessions only, typed columns | baseline (FreeRADIUS-like) |
| + events, typed columns only | cost of history |
| + events, residual JSON | proposed history default |
| + events, raw `bytea` | binary alternative |
| + events, separate payload table | independent payload retention |
| + one targeted expression index / full GIN | cost of attribute queries |
| `COPY` + merge vs multi-row `INSERT`, by batch size | where each write path wins |

Measured: sustained and catch-up rows/s, batch p95/p99, exporter CPU and allocation, PostgreSQL CPU and I/O,
heap / TOAST / index sizes, WAL bytes per event, HOT-update ratio and dead tuples of `accounting_session`,
autovacuum activity, query latency for session history and attribute filters. Traffic: synthetic vendor mix,
replaced by anonymised captures when available (repeated, long and binary attributes, retransmits, out of
order). Defaults (`fillfactor`, batch size, write path, history encoding) are chosen from these numbers.
- **Result so far (2026-11-08):** `sinks/postgres` with the transaction above; COPY in **text** format (binary
  COPY deferred: text is simpler and fast enough so far — to be compared in the benchmark), migrations through
  `SqlMigrations`, partitions created ahead and dropped with `DETACH … CONCURRENTLY`, closed-session retention,
  optional `radacct` view, data errors written row by row with failures to `quarantine`. `PostgresSinkTest`
  (8 tests, PostgreSQL 17): idempotent rewrite, update-only-if-newer, closures keep known values, epoch
  fencing, broken connection leaves nothing behind, three members migrate once, `validate`/`none` never run
  DDL, retention, `radacct` view. Found: the retention query listed partitions of every schema — now limited
  to the sink's own schema. `PostgresExportIT` (3 members, one PostgreSQL, ~3k req/s, exporting member
  stopped): lease moved with epoch 2, 47,923 applied events = 47,923 distinct rows, all 3,000 sessions equal
  the replicated state. The benchmark matrix is still open (moves to `ExportThroughputIT`, P3.9).

### P3.5: LogPurger (size M)

- Purge after each snapshot as in ADR 0014; dry run; metrics for purged bytes.
- ✅ **Done when:** disk bounded over hours of load; restart and follower catch-up after a purge; purge never
  passes a required checkpoint.
- **Result (2026-11-08):** `LogPurger` on every member's scheduler (`log.purge.interval`, default 1 min;
  `log.purge.dry.run`; `archive.segment.length`, default 128 MiB). The "slowest follower" bound is replicated:
  every member reports its own log position (`MemberLogPosition`, schema 2), every member derives the same
  floor, and a member that stops reporting holds it — its log is never purged out from under it. Old snapshot
  recordings below the second-latest snapshot are deleted too. `LogPurgeIT` (4 MiB segments, 1 s interval):
  all members purge below 4 MiB after two snapshots (bounded by the second-latest snapshot); with a follower
  stopped the others purge up to its last reported position (bounded by the slowest member) and it catches up
  after restarting. Hours-long disk boundedness moves to `PurgeIT` (linux, P3.9). Found while testing: whole load-generator
  ports (256 requests) lost every response although the gateways answered every datagram (counters matched
  exactly). Cause: `radclient load` bound its ports to the wildcard address, and Aeron clients in the same host
  (the new member reporter, the lease client) bind `127.0.0.1:0` with address reuse — macOS may hand them a port
  the generator already holds, and unicast then goes to the more specific socket. The generator now binds to
  loopback when its servers are local and counts unmatched and unsendable datagrams. Test-tool issue only: a
  gateway listens on a fixed port outside the ephemeral range.

### P3.6: Metrics and monitoring (size M)

- `/metrics` (Prometheus text format, `# HELP` / `# TYPE`, `radiusward_` prefix, base units: seconds,
  bytes) on every member and gateway:

| Area | Metrics |
|---|---|
| Export | lag per sink (bytes, seconds), rows written, batch latency, errors and retries, quarantined records, lease owner and epoch, detached flag, `EXPORT_LAG` rejections |
| Cluster member | role, term, commit position, applied / duplicates / stale / rejected, active and stopped sessions, snapshots, disk free, purged bytes, dropped log messages |
| Gateway | received, committed, response-cache hits, resubmitted (retransmit, new leader), pending-full and ring drops, back pressure, timeouts, cluster connects |
| JVM | heap, GC pauses, threads, uptime |

- Example Prometheus alert rules (`deploy/monitoring/alerts.yml`): export lag > 50 % of `maxLag`, sink
  detached, no leader / frequent elections, disk free below `cluster.disk.min.free`, gateway drops rising.
- Compose profile `monitoring`: Prometheus + Grafana with one dashboard
  (`docker compose --profile monitoring up`).
- ✅ **Done when:** a test parses `/metrics` of every component (format and names pinned); the alert rules
  pass `promtool check rules`; the compose dashboard shows lag during `PostgresOutageIT`-style runs.
- **Result (2026-11-08):** `PrometheusWriter` (+ `validate`) and `JvmMetrics` in `common`, `/metrics` on members
  and gateways, metric list in [monitoring.md](../operations/monitoring.md); `EXPORT_LAG` rejections and sink
  errors counted separately. 10 alert rules in `deploy/monitoring/alerts.yml`, compose profile `monitoring`
  (Prometheus v3.16.0, Grafana 13.3.0, dashboard with 8 panels). Checked: format pinned in `ThreeNodeClusterIT`
  and `LocalClusterIT`, `promtool` in `MonitoringConfigIT`, `/metrics` in `ComposeSmokeIT`; live in compose all
  5 targets up, applied counts equal on all members, no alert firing. The lag dashboard during an outage is
  checked with `PostgresOutageIT` (P3.9).

### P3.7: Tools (size S)

- `admin verify-export` (cluster sessions and ack log against the database), `admin sinks` (checkpoint, lag,
  lease, epoch, detached), `admin resync <sink> --from <position>`, `admin export-schema --sink <name>`.
- **Result (2026-11-08):** `admin sinks`, `admin resync --sink --position`, `admin export-schema [--type]`,
  `admin verify-export` (ack log against `accounting_session`, and against the cluster with `--members`).
  New schema-2 messages `SinkQuery`/`SinkReport`/`SinkResync`; a resync lowers the checkpoint, fences the
  exporter with a new epoch, and the next lease grant carries a resync flag so the exporter starts from the
  checkpoint instead of the sink's own position. `PostgresExportIT`: verify-export clean for 3,000 sessions,
  `sinks` shows the handover, `resync` to 0 re-exports the whole log with the same 47,843 distinct rows.

### P3.8: Compose and image (size S)

- PostgreSQL service in compose, exporter configuration, demo queries; `demo-failover.sh` also verifies the
  export.
- **Result (2026-11-08):** PostgreSQL 17 at 172.28.0.40 in the default compose stack, `export.sinks=pg`
  (sessions + `radacct` view), `deploy/compose/sql/examples.sql`. `demo-failover.sh`: leader and exporter
  killed at 2k req/s → 59,907 events acknowledged, 0 retransmissions, the lease moved (epoch 2), lag back to 0,
  `verify-export` 10,000 of 10,000 sessions equal to the cluster. Linux tests disable the compose sink unless a
  test configures one (`RADIUSWARD_EXPORT_SINKS=`).

### P3.9: Tests (size L)

| Test | Where | Proves |
|---|---|---|
| `ReducerReplayTest` | unit | the replica reproduces the cluster's outcomes and sessions, incl. out-of-order, Accounting-On/Off |
| `ExportIT` | e2e (Testcontainers, skipped without Docker) | sessions equal the cluster; history exactly once |
| `ExportFailoverIT` | e2e | exporting member `kill -9` → lease and epoch move, no gap, no duplicate, old writer fenced |
| `PostgresOutageIT` | linux | 30 min outage under load, ACKs continue, backlog drains |
| `ExportLagBlockIT` | linux | `required` over `maxLag` → no ACKs, resumes after catch-up |
| `DetachIT` | linux | optional sink detaches, others continue, purge released |
| `PurgeIT` | linux | disk bounded; restart and catch-up after purge |
| `ExportThroughputIT` | linux | benchmark matrix of P3.4, catch-up rate > intake |
| `OverloadIT` (extended) | linux | 2M sessions with the exporter and its replica stay within 1 GiB |

- **Result (2026-11-08):** all green on the Colima VM (outage and purge shortened locally to 3 and 8 minutes;
  the nightly job runs 30 and 60):
  - `PostgresOutageIT`: 74,972 events acknowledged during the outage with 0 failures, lag 7 → 14 MB, backlog drained
    in 49 s, `verify-export` clean.
  - `ExportLagBlockIT`: after 30 s of lag 40k `EXPORT_LAG` rejections and 5k unanswered requests; after recovery
    0 failures; every acknowledged session of all three phases in PostgreSQL.
  - `DetachIT`: detached while PostgreSQL was down, 0 failed ACKs, re-attached, the lease stayed with one member.
  - `ExportThroughputIT`: backlog drain ~27k events/s (sessions) and ~18.5k events/s (with history), table in
    [strategy.md](../testing/strategy.md#export-throughput-phase-3).
  - `PurgeIT`: the largest archive stays at 30–38 MiB while the log grows (snapshots every minute, 4 MiB segments).
  - `OverloadIT` with the exporter: members ≤ 583 MiB unreclaimable of 1 GiB at 2M sessions (448 MiB without the
    exporter; the replica costs ~135 MiB at 2M sessions).
  - Deviations: `ExportIT`/`ExportFailoverIT` as separate e2e process tests were not added — `ExporterIT` and
    `PostgresExportIT` cover the same in a real three-member cluster, and `demo-failover.sh` in compose;
    `ReducerReplayTest` is covered by `LogReplicaSpikeIT` (replica digest equals the cluster's on every member)
    and `BatchBuilderTest`, since cluster and exporter share the same `LogApplier`.
  - Found and fixed: the lease bounced between members while a database hung (blocking JDBC calls outlived the
    lease) — renewals now run on their own thread and the PostgreSQL sink connects with a 5 s timeout; Aeron
    Cluster's default of 10 client sessions was too few with sinks — `cluster.client.sessions.max`, default 256.

### P3.10: Documentation (size M)

- New ADRs: **0017** exporter (inside the member, lease and epoch, commit-position bound, reducer replica,
  checkpoint styles); **0018** storage model (session-first, opt-in history, identities, encoding, PostgreSQL
  schema, idempotency and fencing).
- Amend ADR 0007 (decisions made), ADR 0014 (implemented), the accounting contract (export semantics).
- New `docs/operations/export.md` (modes, queries, `radacct` view, retention, resync, lag alerts, migrating
  from FreeRADIUS SQL) and `docs/sinks/writing-a-sink.md` (SPI, the two primitives, checkpoint styles,
  mappings per target type, driver licensing, packaging for `plugins/`).
- Updates: configuration, failure matrix (P3 rows), architecture, READMEs, CONTRIBUTING / AGENTS,
  THIRD-PARTY (pgjdbc).
- **Result (2026-11-08):** ADR 0017 and 0018 written; ADR 0007 and 0014 amended; accounting contract (export
  section); new [export.md](../operations/export.md), [writing-a-sink.md](../sinks/writing-a-sink.md),
  [monitoring.md](../operations/monitoring.md); configuration (export, purge, client sessions), failure matrix
  (14 P3 rows), architecture, strategy (export tests, throughput), READMEs of every new module, CONTRIBUTING,
  THIRD-PARTY (pgjdbc).

### P3.11: Review (size S)

- Check the exit criteria, record the benchmark matrix, lag recovery and memory; plan Phase 3b / Phase 4.

## Order

```text
P3.1 spike ─▶ P3.2 state ─▶ P3.3 exporter core ─▶ P3.4 postgres ─┐
                                              └──▶ P3.5 purge ────┴─▶ P3.9 tests ─▶ P3.11
P3.6 metrics and monitoring, P3.7 tools, P3.8 compose, P3.10 docs alongside
```

## Risks

| Risk | Handling |
|---|---|
| Coupling to Aeron's log format | spike first; decoder behind one class; test pinned to Aeron 1.54 fails on format changes |
| Replica diverges from the cluster | same code and snapshot codec; digest compared at every checkpoint, mismatch stops the sink with an alert |
| Purging the wrong range loses recovery data | keep two snapshots, never past the slowest follower or required checkpoint, dry-run mode, catch-up tests after purge |
| A sink plug-in harms the member (shared JVM) | own thread, bounded memory, exceptions contained; built-in sinks tested; sidecar mode possible later |
| Two exporters during a lease handover | epoch fence in the sink's checkpoint; writes idempotent |
| Session-table update cost (HOT, vacuum) | no indexes on changing columns, `fillfactor` measured, HOT ratio and dead tuples in the benchmark |
| History volume (100–500 GB/day at 5–1 min interims) | history opt-in with retention; sessions mode is the default |
| JSON cost and correctness | residual attributes only, arrays per attribute, explicit binary encoding, no GIN by default; measured |
| Own migration runner lacks Flyway features | schema is small; Flyway-style SQL files; `export-schema` for DBA-run changes |
| Database slower than intake during catch-up | measure; larger batches or several writer connections by partition |

## Phase 3 report

Measured on an Apple M4 Pro: in-JVM clusters (JDK 21) and Linux containers in a Colima VM (8 CPU, 12 GiB);
PostgreSQL 17 in a container on the same VM. Absolute rates are not bare-metal numbers.

### Exit criteria

| # | Criterion | Result |
|---|---|---|
| 1 | sessions correct | ✅ `verify-export` equal to the cluster for every acknowledged session (in-JVM 3,000, compose 10,000, all linux export tests) |
| 2 | history exactly once | ✅ 47,843–47,945 applied events = as many distinct rows across a lease handover; stale events kept, flagged |
| 3 | outage | ✅ 3 min locally (30 min nightly): ACKs continue, backlog drained in 49 s, nothing lost |
| 4 | crash and handover | ✅ exporting member stopped under load: lease moves with a new epoch, no gap, no duplicate; stale writers fenced |
| 5 | lag policy | ✅ `block` stops ACKs with `EXPORT_LAG` and resumes; `detach` never blocks and re-attaches |
| 6 | disk bounded | ✅ archive 30–38 MiB while the log grows (8 min locally, 60 min nightly); stopped member catches up after a purge |
| 7 | throughput | ✅ backlog drain ~27k events/s (sessions), ~18.5k events/s (history) — 6–9× the test intake, 2–3× the worst-case reference load |
| 8 | memory | ✅ 2M sessions under overload with the exporter: members ≤ 583 MiB unreclaimable of 1 GiB |
| 9 | metrics | ✅ `/metrics` on members and gateways, 10 alert rules (promtool), compose monitoring profile |
| 10 | docs | ✅ ADR 0017, 0018, export, sinks, monitoring guides, configuration, failure matrix |

### Findings worth knowing

- **Aeron log replay ends at elections.** An election stops and later extends the log recording, which ends a
  replay that follows it; the reader restarts from its position. Found by the spike's live tail.
- **Aeron Cluster allows 10 client sessions by default** — not enough once every member runs lease clients;
  `cluster.client.sessions.max` (256).
- **Archive segment length is fixed per recording**: changing `archive.segment.length` affects new recordings
  only (found by CI, where a test changed it after the recording existed).
- **Lease and sink I/O must be independent**: JDBC calls hanging on a stopped database outlived the lease, which
  then bounced between members; renewals now run on their own thread.
- **macOS loopback and wildcard binds**: a load generator bound to `0.0.0.0` lost whole ports of responses to
  Aeron sockets bound to `127.0.0.1` with address reuse. Test-tool issue; the generator binds loopback now.
- The PostgreSQL retention query first looked at partitions of every schema — limited to the sink's own schema.
- With the load generator's attributes the residual JSON is empty; its real cost needs vendor captures.
- Found in the final regression run: `RADIUSWARD_EXPORT_SINKS=` (empty), documented as "no exporter", was rejected
  as a missing key and stopped members from starting; an empty list now disables the exporter
  (`SinkConfigTest`). The admin client also re-sends a query without a reply after 5 s.
- Found by the coverage work (`-Pcoverage`, [strategy](../testing/strategy.md#coverage)): a partition created in
  a rolled-back transaction stayed in the PostgreSQL sink's partition cache, so later good rows for that day
  failed and went to quarantine — a rollback now clears the cache. The admin client did not notice that the
  cluster had closed its idle session (no keep-alives) and now reconnects.
- Found by the first nightly `PurgeIT` (60 min of load): `admin verify-export` read the whole ack log (≈2M lines)
  into a 64 MB heap — the image's default for tools — and ran out of memory before checking anything. The verifiers
  now stream the log keeping one event per session, and `admin` gets a 256 MB heap in the image.

### Deviations from the plan

| Plan | What was done | Why |
|---|---|---|
| binary `COPY` | text `COPY` | simpler, fast enough (≥18.5k events/s); binary stays an option |
| zero-copy batch views | records (copies) | bounded by `batch.rows`, simpler for plug-in authors |
| e2e `ExportIT`, `ExportFailoverIT` | `ExporterIT`, `PostgresExportIT` (in-JVM, three members), `demo-failover.sh` | same scenarios with less machinery |
| `ReducerReplayTest` | `LogReplicaSpikeIT`, `BatchBuilderTest` | cluster and exporter share `LogApplier`; the digest comparison is the stronger check |
| slowest-follower bound via the leader | replicated `MemberLogPosition` reports | deterministic on every member; a silent member holds the floor |
| full benchmark matrix | storage variants only | GIN / expression indexes and a payload table matter only for attribute-heavy history — Phase 3b |

### Open items

- Real vendor captures (residual JSON cost, vendor event-key rules).
- Phase 3b: generic JDBC sink with dialects (MySQL/MariaDB, SQL Server, Oracle, Db2, Firebird, SQLite), Kafka sink;
  remaining benchmark variants.
- Phase 4: Helm chart, Kubernetes, dashboards per deployment; the exporter as a sidecar if isolation is needed.
- First release tag when the maintainer decides (done: `v0.1.0-rc.1`, 2026-11-11).
