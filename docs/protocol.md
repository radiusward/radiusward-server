# Cluster protocol

> **Status: draft.** Finalised in Phase 1 together with the SBE schema in the `protocol` module.

Gateways, the cluster and the exporter talk SBE-encoded messages over Aeron Cluster ingress/egress.
RADIUS bytes never cross this boundary unparsed except as the opaque `rawAttributes` field kept for
export.

## Messages

| Message | Direction | Purpose |
|---|---|---|
| `AccountingCommand` | gateway → cluster | one accounting event to apply |
| `AccountingCommitted` | cluster → gateway | the event is committed (or was a duplicate); gateway may answer the NAS |
| `AccountingRejected` | cluster → gateway | not applied (e.g. a required sink over `maxLag`); gateway stays silent |
| `ExportCheckpoint` | exporter → cluster | sink `sinkId` has durably written everything up to `logPosition` |
| `ActivateVersion` | operator → cluster | switch state-machine behaviour at a log position (ADR 0005) |

### `AccountingCommand` (draft)

| Field | Type | Notes |
|---|---|---|
| `correlationId` | int64 | per gateway attempt; matches the response |
| `gatewayId` | int32 | |
| `operationKey` | 128 bit | logical event key hash (ADR 0003), stable across retries and gateways |
| `nasId` | int32 | configured NAS identity, not the source port |
| `statusType` | uint32 | |
| `sessionTime` | uint32 | |
| `eventTimestamp` | uint32 | 0 if absent |
| `inputOctets64`, `outputOctets64` | uint64 | gigawords already combined |
| `sessionId` | var string | |
| `rawAttributes` | var bytes | attribute section of the request, for the exporter |

### `AccountingCommitted` (draft)

| Field | Type | Notes |
|---|---|---|
| `correlationId` | int64 | |
| `operationKey` | 128 bit | |
| `duplicate` | bool | true if the event had been applied before |
| `logPosition` | int64 | position of the original event |

## Versioning rules

- SBE schema id fixed; `version` increments on every change; fields are only appended.
- A node must replay any log written by an earlier version identically — behaviour changes are gated by
  `ActivateVersion` at a log position, never by deploying new code alone (ADR 0005).
- Gateways and the cluster may run different versions during a rolling upgrade: the cluster accepts
  commands of version N-1.
