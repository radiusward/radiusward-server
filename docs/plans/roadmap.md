# Roadmap

| Phase | Scope | Runs on | Status |
|---|---|---|---|
| **0** | Repo, build, CI; RADIUS codec; FreeRADIUS dictionaries + parser; code generation; vendor fixtures; allocation test + JMH; radclient; docs, ADRs, contributor guide | local | ✅ done ([report](phase-0.md#phase-0-report)) |
| **1** | SBE protocol; Aeron Cluster (3 local nodes) with AccountingService, per-session dedup, snapshots; gateway (NIO UdpAgent, response cache, ClusterClientAgent); NAS registry; in-JVM harness, dev mode, `run-local.sh`; e2e tests (`-Pe2e`): ACK-after-commit, kill -9 failover, retransmit + cross-gateway dedup, node restart | local, no Docker | ✅ done ([plan + report](phase-1.md)) |
| **2** | One container image (`cluster-node | gateway | exporter`), docker-compose; Linux durability tests (fsync, power loss), quorum loss, overload with `--memory=1g`; memory profiles; release images on Java 25 to GHCR | Docker | next — [plan](phase-2.md) |
| **3** | Exporter tailing the log; sink SPI; Postgres sink (COPY + ON CONFLICT), lag policy, Prometheus metrics; Testcontainers | Docker | planned |
| **4** | Helm chart (StatefulSet, PDB, anti-affinity, UDP LB with source IP preservation), systemd units, observability dashboards, chaos and load tests, ClusterBackup / DR runbooks | Kubernetes, bare metal | planned |
| **5** | Authentication/authorization (external auth adapter → cluster decision), EAP design review, RadSec | | planned |

Open questions: Kubernetes target (cloud LB vs bare metal/MetalLB), GitHub owner (GHCR path),
Maven Central publishing.
