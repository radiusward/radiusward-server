# Roadmap

| Phase | Scope | Runs on | Status |
|---|---|---|---|
| **0** | Repo, build, CI; RADIUS codec; FreeRADIUS dictionaries + parser; code generation; vendor fixtures; allocation test + JMH; radclient; docs, ADRs, contributor guide | local | ✅ done ([report](phase-0.md#phase-0-report)) |
| **1** | SBE protocol; Aeron Cluster (3 local nodes) with AccountingService, per-session dedup, snapshots; gateway (NIO UdpAgent, response cache, ClusterClientAgent); NAS registry; in-JVM harness, dev mode, `run-local.sh`; e2e tests (`-Pe2e`): ACK-after-commit, kill -9 failover, retransmit + cross-gateway dedup, node restart | local, no Docker | ✅ done ([plan + report](phase-1.md)) |
| **2** | One container image, docker-compose; failover without NAS retransmissions; Linux fault-injection tests (power loss with LazyFS, partition, full disk, overload at 2M sessions in 1 GiB); latency and memory measured; CI e2e, nightly linux tests, release workflow (GHCR, amd64 + arm64) | Docker | ✅ done ([plan + report](phase-2.md#phase-2-report)); first RC tag pending |
| **3** | Exporter tailing the log; sink SPI; Postgres sink (COPY + ON CONFLICT), lag policy, Prometheus metrics; Testcontainers | Docker | next |
| **4** | Helm chart (StatefulSet, PDB, anti-affinity, UDP LB with source IP preservation), systemd units, observability dashboards, chaos and load tests, ClusterBackup / DR runbooks | Kubernetes, bare metal | planned |
| **5** | Authentication/authorization (external auth adapter → cluster decision), EAP design review, RadSec | | planned |

Open questions: Kubernetes target (cloud LB vs bare metal/MetalLB), Maven Central publishing.
