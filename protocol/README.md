# radiusward-protocol

`radiusward-protocol` holds the SBE messages that RADIUS servers, cluster members, the exporter and the admin tools
exchange through Aeron Cluster, and the snapshot format of the replicated state. The schema is
`src/main/resources/sbe/radiusward-schema.xml` (schema id 7101, version 8, little endian); `sbe-tool` generates the
Java codecs into `io.radiusward.protocol` at `generate-sources`, so the runtime needs only Agrona.

**Stability:** Internal: published as a dependency of `radiusward-embedded` and the radiusward server; it may change in any release.

## Use it

You normally do not depend on it directly: the radiusward server, the cluster modules and `radiusward-embedded`
bring it. Plug-in writers never see these messages: sinks receive events through `radiusward-export-api`, identity
stores and verifiers work through `radiusward-auth-api`.

## What's inside

| Messages | Role |
|---|---|
| `AccountingCommand`, `AccountingCommitted`, `AccountingRejected` | one accounting event from a RADIUS server; the cluster's answer: committed (or a duplicate or stale), so the NAS may be answered, or not applied, so the server stays silent |
| `AuthReservation`, `SqnNext` and their results | simultaneous-use reservations (v6) and the next EAP-AKA sequence number of a SIM subscriber (v8) |
| `ExportCheckpoint`, `ExportCheckpointAck`, `MemberLogPosition` | the exporter's sink lease and checkpoint (v2); a member's log position for purging and its supported state version |
| `ActivateVersion`, `SinkQuery`, `SinkResync`, `SinkReport` | admin commands: activate a state version, sink status and resync |
| `StateQuery`, `SessionQuery`, `UserSessionsQuery`, `SessionPageQuery` and their reports | read-only questions answered from the replicated state |
| `SnapshotHeader` … `SnapshotFooter` | the snapshot: sessions, exact keys, sinks, member positions, reservations, sequence numbers |
| `MessageHeaderDecoder`, `MessageHeaderEncoder` | the SBE header (`schemaId`, `templateId`, version) in front of every message |

Every message has a generated `…Encoder` and `…Decoder`; the full list with ids and directions is in
[docs/protocol.md](../docs/protocol.md).

**Versioning rules.** Fields are only appended, each new one with `sinceVersion`; ids are never reused; the schema
version increments with every change. A test schema (`src/test/resources/sbe/radiusward-schema-v2-test.xml`) and
`ProtocolRoundTripTest` prove that v1 decoders read v2 messages. Behaviour changes are activated at a log position,
never by deploying code alone ([ADR 0005](../docs/adr/0005-log-determinism-versioning.md)).

## Example

How the cluster service dispatches a message, without allocating:

```java
MessageHeaderDecoder header = new MessageHeaderDecoder();      // reused
header.wrap(buffer, offset);
if (header.schemaId() == MessageHeaderDecoder.SCHEMA_ID) {
    switch (header.templateId()) {
        case AccountingCommandDecoder.TEMPLATE_ID -> command.wrapAndApplyHeader(buffer, offset, header);
        case StateQueryDecoder.TEMPLATE_ID -> query.wrapAndApplyHeader(buffer, offset, header);
        default -> { }                                         // unknown message: ignored
    }
}
```

## Requirements

Java 25 and `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` (Agrona). Runtime dependency: Agrona
(Apache-2.0); `sbe-tool` is used at build time only.

## Learn more

- [Cluster protocol](../docs/protocol.md): every message, its fields and versions
- [ADR 0005: log determinism and versioning](../docs/adr/0005-log-determinism-versioning.md)
- [ADR 0001: Aeron Cluster](../docs/adr/0001-aeron-cluster.md)
- [radiusward-cluster-service](../cluster-service/README.md): the service that applies these messages

## License

Apache-2.0.
