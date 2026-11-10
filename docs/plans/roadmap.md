# Roadmap

| Phase | Scope | Runs on | Status |
|---|---|---|---|
| **0** | Repo, build, CI; RADIUS codec; FreeRADIUS dictionaries + parser; code generation; vendor fixtures; allocation test + JMH; radclient; docs, ADRs, contributor guide | local | ✅ done ([report](phase-0.md#phase-0-report)) |
| **1** | SBE protocol; Aeron Cluster (3 local nodes) with AccountingService, per-session dedup, snapshots; gateway (NIO UdpAgent, response cache, ClusterClientAgent); NAS registry; in-JVM harness, dev mode, `run-local.sh`; e2e tests (`-Pe2e`): ACK-after-commit, kill -9 failover, retransmit + cross-gateway dedup, node restart | local, no Docker | ✅ done ([plan + report](phase-1.md)) |
| **2** | One container image, docker-compose; failover without NAS retransmissions; Linux fault-injection tests (power loss with LazyFS, partition, full disk, overload at 2M sessions in 1 GiB); latency and memory measured; CI e2e, nightly linux tests, release workflow (GHCR, amd64 + arm64) | Docker | ✅ done ([plan + report](phase-2.md#phase-2-report)); first RC tag pending |
| **3** | Exporter tailing the log; sink SPI (stable `export-api`); Postgres sink (COPY + ON CONFLICT) and file sink, lag policy, log purge, Prometheus metrics; Testcontainers | Docker | ✅ done ([plan + report](phase-3.md#phase-3-report)) |
| **3b** | Generic JDBC sink with dialects for the relational databases below; Kafka sink | Docker | next |
| **4** | Helm chart (StatefulSet, PDB, anti-affinity, UDP LB with source IP preservation), systemd units, observability dashboards, chaos and load tests, ClusterBackup / DR runbooks | Kubernetes, bare metal | planned |
| **5** | Authentication and authorization (identity stores, Active Directory, EAP-TLS/PEAP/TTLS/TEAP/pwd), Simultaneous-Use through the cluster, RadSec, DTLS, CoA/Disconnect, proxying | local, Docker | ✅ done: 5.1–5.18 ([plan](phase-5-auth.md)) |

State-machine versions are gated since 2026-11-09 ([ADR 0005](../adr/0005-log-determinism-versioning.md)): version 5 is
the baseline of the first release; every later rule change gets a new version and `atLeast(n)`, activated by the
cluster once all members run it.

## Sinks

Every target is a plug-in behind the same `AccountingSink` SPI ([ADR 0007](../adr/0007-sink-spi-lag-policy.md)):
the exporter core does reading, batching, retry, checkpoints, failover and lag for all of them; a sink only
writes a batch durably and must be **idempotent by `event_id`** (writing an event twice changes nothing).
Deployments usually run one sink; several at once are supported, each holding the log until it has caught up.

**Drivers are not bundled unless their licence allows it** (the image is Apache-2.0). Other sinks ship as
separate plug-ins; the operator adds the plug-in and the driver to `plugins/`.

### Relational databases

| Database | Phase | Sink | Idempotent write | Fast path | JDBC driver (licence) | Bundled |
|---|---|---|---|---|---|---|
| PostgreSQL 16+ | 3 | `postgres` (built in) | `INSERT … ON CONFLICT DO NOTHING` | binary `COPY` into staging | pgjdbc (BSD-2-Clause) | yes |
| MySQL 8+ / MariaDB 10.6+ | 3b | `jdbc`, dialect `mysql` | `INSERT IGNORE` / `ON DUPLICATE KEY UPDATE` | multi-row `INSERT`, `rewriteBatchedStatements` | MariaDB Connector/J (LGPL-2.1) for both; MySQL Connector/J is GPL-2.0 + FOSS exception | no |
| Microsoft SQL Server 2019+ / Azure SQL | 3b | `jdbc`, dialect `sqlserver` | `MERGE` / insert where not exists | bulk copy into staging, then `MERGE` | mssql-jdbc (MIT) | possible |
| Oracle 19c+ | 3b | `jdbc`, dialect `oracle` | `MERGE` or `IGNORE_ROW_ON_DUPKEY_INDEX` | array insert into staging, then `MERGE` | ojdbc (Oracle Free Use Terms) | no |
| IBM Db2 11.5+ (LUW) | 3b | `jdbc`, dialect `db2` | `MERGE` | array insert into staging, then `MERGE` | IBM Data Server Driver (IBM licence) | no |
| Firebird 4+ | 3b | `jdbc`, dialect `firebird` | `UPDATE OR INSERT … MATCHING` / `MERGE` | batched `INSERT` | Jaybird (LGPL-2.1) | no |
| SQLite 3 | 3b | `jdbc`, dialect `sqlite` | `INSERT OR IGNORE` | one transaction per batch, WAL mode; single writer, for small sites and labs | sqlite-jdbc (Apache-2.0) | possible |

Compatible databases reuse an existing dialect after a test run: **CockroachDB, YugabyteDB, TimescaleDB,
Citus** (PostgreSQL protocol; `COPY` support differs), **TiDB, Percona Server, Amazon Aurora** (MySQL or
PostgreSQL), **Amazon RDS / Azure Database / Cloud SQL** (managed PostgreSQL, MySQL, SQL Server).

Candidates not yet scheduled (relational and analytical): SAP HANA, Informix, H2 (tests only), and the
warehouses ClickHouse, Snowflake, Amazon Redshift, Google BigQuery, which want large batch loads instead of
row inserts.

### Streams and NoSQL

| Target | Phase | Idempotency | Notes |
|---|---|---|---|
| Apache Kafka (and Redpanda, Amazon MSK, Azure Event Hubs via the Kafka protocol) | 3b | key = `event_id`, idempotent producer; consumers deduplicate or use compaction | recommended hub when several systems need the data: export once, consume many times |
| Apache Pulsar, NATS JetStream, RabbitMQ streams | later | message id / dedup window = `event_id` | |
| Apache Cassandra / ScyllaDB | later | primary key `event_id`; rewriting the same row is harmless (no `IF NOT EXISTS`) | unlogged batches per partition |
| Amazon DynamoDB | later | `PutItem` with `attribute_not_exists(event_id)` or identical overwrite | `BatchWriteItem` (25 items) |
| MongoDB | later | `_id` = `event_id`, unordered `insertMany`, duplicate-key errors ignored | |
| Elasticsearch / OpenSearch | later | document id = `event_id` | bulk API; for search and dashboards |
| Object storage (S3, GCS, Azure Blob) as Parquet / JSON lines | later | file names by log position range | archive and data lakes |

Open questions: Kubernetes target (cloud LB vs bare metal/MetalLB), Maven Central publishing.
