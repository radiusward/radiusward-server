# test-harness

Runs radiusward inside one JVM.

- `LocalCluster` — N cluster members and M gateways on loopback with temp directories and free ports;
  `awaitLeader()`, `stopNode(i)`, `startNode(i)`, `awaitConverged()`, `admin()`.
- `AdminClient` — `StateQuery` / `SessionQuery` through the cluster log.
- `DevCluster` — dev mode with the same ports as `scripts/run-local.sh` (IntelliJ: `.run/DevCluster.run.xml`).

`LocalClusterIT`: all vendor fixtures through a gateway, retransmit via the other gateway, leader loss,
snapshot + full restart, load through both gateways.
