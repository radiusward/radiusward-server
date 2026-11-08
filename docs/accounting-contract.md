# Accounting contract

What a NAS — and the operator — can rely on when radiusward answers, or does not answer, an
Accounting-Request. Applies from Phase 1; Phase 0 provides the codec that implements the wire side.

## The guarantee

> When radiusward sends an **Accounting-Response**, the accounting record has been appended to the
> replicated log and **fsynced on a majority of cluster nodes** (2 of 3), under the configured
> persistence policy (`aeron.archive.file.sync.level=2`). It survives the loss of any single node,
> including power loss of that node.

The response is sent only after the cluster reports `AccountingCommitted` for the request. It is
**not** sent after a local queue hand-off, after an Aeron `offer()` succeeded, or after a single node
received the command.

The acknowledgment means "recoverable from the cluster". It does **not** mean "written to the billing
database": sinks are fed asynchronously from the committed log (Phase 3). An operator who needs
database completion before the ACK would need a different contract; it is not offered.

## When there is no response

RADIUS has no Accounting-Reject. radiusward stays **silent** and the NAS retransmits when:

- the packet is malformed, the source is not a configured NAS, or an authenticator does not verify
  (silently discarded, RFC 2865 §3 / RFC 2866 §4.1);
- a gateway queue is full (bounded admission control);
- no cluster majority is reachable, or a leader election is in progress;
- storage synchronisation fails;
- a sink marked `required: true` has exceeded its `maxLag` (`onMaxLag: block`).

Silence never means the record was lost *after* an ACK. It means the NAS still owns the record and
must retry or buffer it, which NAS devices do.

## Duplicates and retries

A missing response does not tell the NAS whether the original was committed, so retries are normal —
also after a leader failover and through a different gateway.

| Layer | Recognises | Key |
|---|---|---|
| Gateway response cache (RFC 5080 §2.2.2) | identical retransmits arriving at the same gateway | source IP:port, Identifier, Request Authenticator |
| Cluster dedup | the same accounting event however it arrives | logical event key per NAS and session (below) |

A duplicate is answered with an Accounting-Response — the original outcome — and is **not** applied
or exported a second time.

**Logical event key** (per vendor `EventKeyStrategy`, ADR 0003): NAS identity, `Acct-Session-Id`,
`Acct-Status-Type`, and `Acct-Session-Time` or `Event-Timestamp`. It deliberately **excludes**
`Acct-Delay-Time` (changes on every retransmit, which also changes the authenticator) and the RADIUS
Identifier (8 bits, reused). Interim updates are deduplicated per session: an interim that is not newer
than the last applied one is a duplicate.

Dedup state is part of the snapshots and survives restarts. Retention: per-session state lives as long
as the session (plus a Stop tombstone window); the exact-key window for events without a monotonic
field is bounded (default 15 minutes, configurable). A retransmit older than that window can be applied
twice; downstream sinks are idempotent by `event_id` as a second line of defence.

## Response content

- Code 5 (Accounting-Response), same Identifier as the request.
- All `Proxy-State` attributes of the request, in order (RFC 2865 §5.33).
- Response Authenticator = MD5(Code + Identifier + Length + Request Authenticator + Attributes + Secret).
- Optional Message-Authenticator (configurable per NAS).

Implemented by `AccountingResponses` in `radius-codec`.

## Export to databases (Phase 3)

Sinks are fed asynchronously from the committed log ([ADR 0017](adr/0017-exporter.md),
[ADR 0018](adr/0018-storage-model.md)):

- **What reaches a sink** is what the cluster applied: applied events (and stale ones, flagged, in the history),
  and every session as the cluster holds it after each change — including sessions closed by Accounting-On/Off
  or the idle timeout. Duplicates and rejected events are never exported.
- **Delivery** is at least once from the exporter's point of view and exactly once in the database: events are
  inserted only if absent (`event_id`), sessions updated only if newer (`projection_version`), and the sink's
  checkpoint is fenced by the exporter's lease epoch, so a replaced exporter cannot write.
- **Delay:** normally milliseconds to seconds. While a sink is down the log on disk is the buffer and ACKs
  continue; a `required` sink more than `maxLag` behind (default 4 h) stops new ACKs (`EXPORT_LAG`, the NAS
  retries) until it catches up; an optional sink is detached instead (the log is no longer held for it; a gap is
  repaired with `radiusward admin resync` while the log still holds the position).
- **Check it:** `radiusward admin verify-export` compares an acknowledgement log with the database and the cluster.

## Failure model

Tolerated without losing acknowledged records: one cluster node lost (crash, power loss, disk loss),
any number of gateways lost, network partitions that leave a majority connected, sink outages up to
`maxLag`.

Not tolerated: losing two of three nodes at once (no majority — the cluster stops ACKing; data on the
surviving node is intact but the cluster is unavailable until a majority returns). Disaster recovery
beyond that relies on Aeron ClusterBackup (Phase 4).

## Verification

Each statement above maps to a test in [testing/failure-matrix.md](testing/failure-matrix.md). Durability
under power loss has to be verified on Linux (macOS `fsync` does not flush the drive cache).
