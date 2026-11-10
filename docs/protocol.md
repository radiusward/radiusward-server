# Cluster protocol

SBE messages between gateways, the cluster and tools, plus the snapshot format. Schema:
[`protocol/src/main/resources/sbe/radiusward-schema.xml`](../protocol/src/main/resources/sbe/radiusward-schema.xml)
(schema id 7101, version 8, little endian); Java codecs are generated at build time into
`io.radiusward.protocol`.

## Messages

| Id | Message | Direction | Purpose |
|---|---|---|---|
| 1 | `AccountingCommand` | gateway → cluster | one accounting event |
| 2 | `AccountingCommitted` | cluster → gateway | applied, duplicate or stale — answer the NAS |
| 3 | `AccountingRejected` | cluster → gateway | not applied (capacity) — stay silent |
| 4 / 5 | `SessionQuery` / `SessionReport` | admin → cluster → admin | one session's replicated state; v7: its identifying attributes |
| 6 / 7 | `StateQuery` / `StateReport` | admin → cluster → admin | totals and state digest |
| 8 / 9 | `ExportCheckpoint` / `ExportCheckpointAck` | exporter → cluster → exporter | v2: sink lease and checkpoint (ADR 0017) |
| 10 | `MemberLogPosition` | member → cluster | v2: log position for purging; v5: supported state version |
| 11–13 | `SinkQuery`, `SinkReport`, `SinkResync` | admin ↔ cluster | v2: sink status and resync |
| 14 / 15 | `ActivateVersion` / `ActivateVersionResult` | admin → cluster → admin | v5: state versions (ADR 0005) |
| 16 / 17 | `AuthReservation` / `AuthReservationResult` | gateway → cluster → gateway | v6: simultaneous use (ADR 0023) |
| 18 / 19 | `UserSessionsQuery` / `UserSessionsReport` | admin, gateway → cluster | v7: a user's active sessions with their identifying attributes (ADR 0036) |
| 29 / 30 | `SqnNext` / `SqnResult` | gateway → cluster → gateway | v8: the next EAP-AKA sequence number of a SIM subscriber (ADR 0061) |
| 27 / 28 | `SessionPageQuery` / `SessionPageReport` | gateway → cluster | v7: a page of active sessions with a user (the store sweep) |
| 20–23 | `SnapshotHeader`, `SessionChunk`, `ExactKeyChunk`, `SnapshotFooter` | snapshot | state machine snapshot |
| 24 / 25 | `SinkChunk`, `MemberPositionChunk` | snapshot | v2: sinks, member positions |
| 31 | `SqnChunk` | snapshot | v8: subscribers' sequence numbers, sorted by key, only when there are any |
| 26 | `ReservationChunk` | snapshot | v6: reservations, only when there are any; `SessionChunk` v7: first event and identifying attributes per session |

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
| `userKey`, `deviceKey` | int64 ×2 | v6: User-Name hash (ASCII case folded) and Calling-Station-Id key (a MAC as its 48 bits, else a hash); 0 = absent; recorded from state version 6 on |
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

### State versions (v5, ADR 0005)

- `MemberLogPosition` (every member, every `log.purge.interval`) appends `supportedVersion`, `clusterSize`, `hold`.
- `ActivateVersion` (`correlationId`, `version`) → `ActivateVersionResult` (`result` `ACTIVATED` \| `NOT_NEWER` \|
  `MEMBERS_NOT_READY`, `activeVersion`, `lowestSupportedVersion`).
- `StateReport` appends `activeVersion`, `lowestSupportedVersion`; `SnapshotHeader` appends `activeVersion`,
  `clusterSize`; `MemberPositionChunk` appends `supportedVersion`, `hold`.

### Simultaneous use (v6, ADR 0023)

- `SqnNext` (`correlationId`, `gatewayId`, `subscriberKey`, `floor`) → `SqnResult` (`correlationId`, `outcome`
  `OK` \| `UNSUPPORTED` \| `CAPACITY`, `sqn`), sent after the commit (state version 8, ADR 0061): the next SEQ above
  the subscriber's last SQN and above `floor` (the store's `SIM-SQN`, or the USIM's after a resynchronisation), with
  IND = 0, at most 48 bits; `service.sim.subscribers.max` bounds the table.
- `AuthReservation` (`correlationId`, `gatewayId`, `userKey`, `deviceKey`, `maxDevices`, `ttlSeconds`) →
  `AuthReservationResult` (`correlationId`, `result` `GRANTED` \| `DENIED` \| `UNSUPPORTED` \| `CAPACITY`), sent after
  the commit. Correlation ids of reservations carry bit 62 and the worker index.
- `SessionChunk` appends `userKey`, `deviceKey`; `SnapshotHeader` appends `reservationCount`; `ReservationChunk`
  (`userKey`, `deviceKey`, `expiry`) is written only when reservations exist, so older code never meets it.

## Versioning rules

- Fields are only appended, with `sinceVersion`; ids are never reused; the schema version increments with
  every change. `ProtocolRoundTripTest` proves a v1 decoder reads a v2 message.
- Behaviour changes are activated at a log position, never by deploying code alone (ADR 0005); snapshots
  carry the state version and a node refuses a snapshot newer than its software.
