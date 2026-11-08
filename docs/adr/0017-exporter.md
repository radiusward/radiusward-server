# ADR 0017: Exporter — inside the member, leased, bounded by the commit position, reducing with the state machine

Status: Accepted (2026-11-08). Phase 3. Refines ADR 0007.

## Context
Committed accounting has to reach databases and streams without coupling the ACK to them (ACK at log commit,
[accounting contract](../accounting-contract.md)), without exporting entries an election could still truncate,
without duplicates, and without RADIUS logic in every sink plug-in.

## Decision
- **Where:** the exporter is an agent inside every cluster member (one thread per sink). The member's own archive
  holds the log and its commit-position counter tells how far the log is committed, so the exporter
  (`ClusterLogReader`) replays the local log recording and never reads past the commit position. An election
  stops and later extends the recording, which ends a following replay; the reader restarts it from its position.
- **Who:** one member exports a sink at a time, chosen by a **lease in the replicated state**
  (`ExportCheckpoint` command, cluster time, default timeout 10 s). A takeover — or the owner's restarted
  exporter — gets a new **epoch**; transactional sinks store the epoch with their checkpoint and refuse writes of
  an older one (fencing). The lease is renewed by its own thread, so a database that hangs on connect or write
  does not let the lease expire.
- **What:** the exporter runs the cluster's own state machine through the shared `LogApplier`, starting from the
  latest snapshot below its checkpoint. It exports only what the cluster decided: applied events (stale ones to
  history, flagged; duplicates and rejected never), the reconciled snapshot of every changed session
  (`projection_version` = log position), and sessions closed without an event of their own (Accounting-On/Off,
  idle timeout). Sinks implement two primitives: events insert-if-absent by `event_id`, sessions
  update-only-if-newer by `projection_version`.
- **Checkpoints and lag:** the sink's own stored position is the resume point (transactional sinks); the cluster
  checkpoint drives lag, the lag policy (`required`/`maxLag`/`block`|`detach`, `EXPORT_LAG` rejection) and the log
  purge (ADR 0014). Lag by time counts from the first entry a sink had not exported after it was last caught up,
  so idle periods never count. `radiusward admin resync` lowers a checkpoint, fences the exporter and makes the
  next exporter start from the checkpoint.
- **Plug-ins:** `export-api` (`AccountingSink`, `SinkProvider` via `ServiceLoader`, jars in `plugins/`), storage
  agnostic and versioned; [writing-a-sink.md](../sinks/writing-a-sink.md).

## Consequences
- Measured: the replica reaches the cluster's digest on every member, through failovers; replay + apply
  0.9–3.6 M commands/s. Lease handover under load: no gap, no duplicate in PostgreSQL (`PostgresExportIT`).
- Memory: the replica costs about the cluster's own session state (~77 bytes per session) per member.
- A sink plug-in shares the member's JVM; built-in sinks are tested, third-party plug-ins run on trust. A
  sidecar container in the member's pod (same `/dev/shm`, same archive) is possible later without redesign.
- Upgrades: protocol and snapshot format version 2. All members must run it before an exporter is enabled — an
  older member would ignore checkpoints and decide `block` differently.
- Aeron Cluster client sessions grow with sinks (two per sink per member) and gateways: `cluster.client.sessions.max`
  (default 256).
