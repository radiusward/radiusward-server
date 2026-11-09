# ADR 0018: Storage model — session-first, opt-in history, stable identities, portable primitives

Status: Accepted (2026-11-08). Phase 3. Reviewed against two external reviews (JSONB/PostgreSQL, FreeRADIUS SQL).

## Context
FreeRADIUS' SQL accounting keeps **one row per session** (`radacct`): Start inserts, Interim updates, Stop closes.
Keeping every Interim as a row costs 100–500 GB per day at the reference load (500k sessions, 5–1 min interims).
The same data has to fit MySQL, SQL Server, Oracle, Db2, Firebird, SQLite, Cassandra, DynamoDB and Kafka later.

## Decision
- **Modes:** `sessions` (default; `accounting_session`, one row per session, optional `radacct` view for
  FreeRADIUS tools), `sessions+events` (plus immutable `accounting_event` history with `events.retention`,
  default 90 days), raw archive (`attributes=raw` or the file sink).
- **Identities:** `event_id` = 128-bit exact key (identical for every retransmission); `session_key` = 128-bit
  session key; history partitioned by the **commit day from the cluster timestamp in the log** (identical on every
  replay, so the partition-scoped primary key stays correct); the source event time is its own column.
- **Primitives every sink implements:** events insert-if-absent, sessions update-only-if-newer; checkpoint
  *transactional* (with the data, epoch-fenced) or *idempotent replay* (Cassandra, DynamoDB).
- **Attributes:** typed columns for what reports query (user, framed IP, NAS IP, calling station, terminate cause,
  counters); the rest as canonical JSON defined once in `export-api` — every attribute an array, binary as
  base64, unknown attributes by number, a format version column, no U+0000; column type per dialect.
- **Values:** counters as signed 64-bit (`bigint`), overflow flagged; missing values `NULL`, never 0.
- **PostgreSQL:** one transaction per batch — `COPY` (text format) into temporary staging, `INSERT … ON CONFLICT
  DO NOTHING` into the history, `INSERT … ON CONFLICT DO UPDATE … WHERE projection_version <` into the sessions
  (values a closure does not know are kept; `started_at` from the Start's Event-Timestamp, derived from the first
  Interim when the Start is late or lost), epoch-fenced `sink_checkpoint`. History `outcome`: 1 applied, 2 stale,
  3 merged (late Start). No indexes on columns that change
  with every Interim (so updates can stay HOT), partial index for online sessions, BRIN on time, no GIN by default.
  Daily partitions created ahead, expired ones `DETACH … CONCURRENTLY`; closed-session retention optional; rows
  with data errors go to `quarantine`. Schema by our own migration runner (`schema.manage`,
  `admin export-schema`).

## Consequences
- A FreeRADIUS SQL user sees the familiar shape (`radacct` view) and pays no history volume unless enabled.
- The session row is exactly the cluster's session: out-of-order Interims, Stop before a delayed Interim and
  Accounting-On/Off are decided once, by the state machine, not re-implemented per database.
- Measured catch-up rates per variant: [testing/strategy.md](../testing/strategy.md#export-throughput-phase-3).
- Rejected for now: `numeric(20,0)` counters (2^63 bytes per session is enough), tenant id, NAS generation.
