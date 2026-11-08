# sink-postgres

`sink.<name>.type=postgres` ([export.md](../../docs/operations/export.md), [ADR 0018](../../docs/adr/0018-storage-model.md)):
`accounting_session` (one row per session, update only if newer), optional `accounting_event` history (daily
partitions, insert if absent), optional `radacct` view; `COPY` into staging and `ON CONFLICT` in one transaction
per batch with an epoch-fenced checkpoint. Schema in `src/main/resources/io/radiusward/sink/postgres/migrations`.
Tests: `PostgresSinkTest` (Testcontainers, skipped without Docker, required in CI).
