# Cluster protocol

SBE messages between gateways, the cluster and tools, plus the snapshot format. Schema:
[`protocol/src/main/resources/sbe/radiusward-schema.xml`](../protocol/src/main/resources/sbe/radiusward-schema.xml)
(schema id 7101, version 1, little endian); Java codecs are generated at build time into
`io.radiusward.protocol`.

## Messages

| Id | Message | Direction | Purpose |
|---|---|---|---|
| 1 | `AccountingCommand` | gateway → cluster | one accounting event |
| 2 | `AccountingCommitted` | cluster → gateway | applied, duplicate or stale — answer the NAS |
| 3 | `AccountingRejected` | cluster → gateway | not applied (capacity) — stay silent |
| 4 / 5 | `SessionQuery` / `SessionReport` | admin → cluster → admin | one session's replicated state |
| 6 / 7 | `StateQuery` / `StateReport` | admin → cluster → admin | totals and state digest |
| 20–23 | `SnapshotHeader`, `SessionChunk`, `ExactKeyChunk`, `SnapshotFooter` | snapshot | state machine snapshot |

### AccountingCommand

| Field | Type | Notes |
|---|---|---|
| `correlationId` | int64 | gateway pending slot + generation; matches the reply |
| `gatewayId` | int32 | |
| `nasId` | int32 | device scope: the configured NAS id, or for an entry with `identity` a 32-bit hash of NAS id and device identity (ADR 0019); the state machine groups sessions and Accounting-On/Off by it |
| `sessionKeyHi/Lo` | int64 ×2 | Murmur3-128 of (NAS id, [length, device identity], Acct-Session-Id) |
| `exactKeyHi/Lo` | int64 ×2 | Murmur3-128 of (NAS id, status, session time, event time, octets, presence, [length, device identity], session id) — no Acct-Delay-Time, no Identifier |
| `nasClientId` | int32 | v3: the configured NAS entry id |
| `identityFingerprint` | int32 | v3: hash of the entry's `identity` setting (gateways must agree) |
| `idleTimeoutMinutes` | uint16 | v4: `nas.<name>.idle.timeout` in minutes, 0 = the cluster's `service.idle.timeout` |
| `nasDevice` | var string | v3: normalised device identity, empty for `source-ip` or when missing (`flags.deviceUnknown`) |
| `statusType` | uint32 | Acct-Status-Type |
| `flags` | set | `sessionTimePresent`, `eventTimestampPresent`, `sessionIdPresent` |
| `sessionTime`, `eventTimestamp` | uint32 | 0 when absent |
| `inputOctets`, `outputOctets` | int64 | gigawords combined |
| `sessionId` | var string | |
| `rawAttributes` | var data | attribute section of the request, kept for export (Phase 3) |

The key layout is pinned by `EventKeysTest` against reference vectors: changing it would make gateways
compute keys the dedup state has never seen.

### AccountingCommitted

`correlationId`, `outcome` (`APPLIED` \| `DUPLICATE` \| `STALE`), `eventId` = log position of the event.

## Versioning rules

- Fields are only appended, with `sinceVersion`; ids are never reused; the schema version increments with
  every change. `ProtocolRoundTripTest` proves a v1 decoder reads a v2 message.
- Behaviour changes are activated at a log position, never by deploying code alone (ADR 0005); snapshots
  carry the state version and a node refuses a snapshot newer than its software.
