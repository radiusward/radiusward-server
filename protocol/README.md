# protocol

SBE messages between gateways, the cluster and tools, and the snapshot format. The schema lives in
`src/main/resources/sbe/radiusward-schema.xml`; `sbe-tool` generates the codecs into
`io.radiusward.protocol` at `generate-sources` (build time only — the runtime needs just Agrona).

Rules: append-only fields with `sinceVersion`, ids never reused, the version increments with every change.
A test schema (`src/test/resources/sbe/radiusward-schema-v2-test.xml`) proves v1 decoders read v2 messages.
Message reference: [docs/protocol.md](../docs/protocol.md).
