# ADR 0007: Pluggable sinks, log-tailing exporter, lag policy

Status: Accepted (2026-11-07)

## Context
Records must reach a database (Postgres first) and possibly Kafka, ClickHouse or files, fast and
without double counting. Holding an export backlog in cluster memory would cost ~4 GB per hour of
database outage.

## Decision
- The **exporter tails the committed cluster log** via Archive replay (preferably on a follower). The
  cluster stores only `ExportCheckpoint(sinkId, logPosition)`; the log is purged below
  `min(snapshot position, slowest sink checkpoint)`.
- **Sinks are plugins**: `AccountingSink` SPI via `ServiceLoader`, jars in a plugins directory, several
  sinks active at once, each with its own thread, cursor, batching and retry.
- Contract: at-least-once delivery, idempotent sinks keyed by `event_id`.
- **Postgres sink:** plain JDBC (no Hibernate — banned by the enforcer), binary `COPY` into a staging
  table + `INSERT ... ON CONFLICT DO NOTHING`, batched multi-row INSERT as fallback, time-partitioned
  tables, one writer connection.
- **Lag policy per sink:** `required`, `maxLag` (size or duration), `onMaxLag`. Default `block` (stop
  ACKing new accounting) for `required: true`, `detach` (release the log, alert, manual resync)
  otherwise. Prometheus lag metrics with early alerts.

## Consequences
- Exporter memory stays flat during long outages; disk (log retention) is the buffer — PVCs ~100 GB.
- Coupling to the Aeron log format needs a spike in Phase 3; fallback is a bounded in-state backlog.
