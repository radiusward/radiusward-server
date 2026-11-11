# Local cluster

Phase 1 runs the full system on one machine without Docker ([ADR 0009](../adr/0009-local-first-development.md)).
Three ways to run it:

| Mode | How | Use |
|---|---|---|
| Separate processes | `scripts/run-local.sh` | the real thing, `kill -9` failover demo |
| Dev mode (one JVM) | run `io.radiusward.testing.DevCluster` in IntelliJ (`.run/DevCluster.run.xml`) | debugging |
| In-JVM test harness | `LocalCluster` in tests (`testing/test-harness`) | integration tests |

## run-local.sh

```bash
scripts/run-local.sh build            # radiusward.jar + radclient.jar
scripts/run-local.sh start            # node-0..2 (cluster ports 9000/9100/9200) + gateway-a (1813) + gateway-b (1814)
scripts/run-local.sh wait-ready
scripts/run-local.sh status           # roles, applied, duplicates, digests
scripts/run-local.sh leader
scripts/run-local.sh kill node-1      # kill -9
scripts/run-local.sh start node-1     # restarts (waits up to 20 s for the dead process's mark file to expire)
scripts/run-local.sh restart gateway-a   # stop and start one process
scripts/run-local.sh logs gateway-a
scripts/run-local.sh demo-failover    # load through both gateways, kill -9 the leader at t=10 s
scripts/run-local.sh stop | clean     # clean also deletes .local/
```

Configuration: [config/local](../../config/local) (`cluster.properties` + `node-<i>.properties`,
`gateway-<a|b>.properties` + `nas-clients.properties`; NAS `127.0.0.1`, secret `testing123`). Nodes run with
`-Xmx256m -XX:MaxDirectMemorySize=576m` (small profile; sessions are off-heap). State, logs and pid files are in `.local/`.

Send traffic:

```bash
RADCLIENT="java -jar tools/radclient/target/radclient.jar"
$RADCLIENT acct --server 127.0.0.1:1813 --secret testing123 --status start --session-id s1 --vendor cisco
$RADCLIENT load --server 127.0.0.1:1813,127.0.0.1:1814 --secret testing123 --sessions 1000 --rate 1000 --duration 30s
curl -s 127.0.0.1:9090/state
```

## Failover demo

`demo-failover` starts everything, runs 1,000 sessions at up to 1,000 req/s through both gateways for 30 s,
and `kill -9`s the leader after 10 s. Expected result (measured on an M4 Pro): every event acknowledged
(`failed 0`), the gateways resubmit the commands lost with the old leader, the outage shows as p99 latency
of ~6 s (3 s leader heartbeat timeout + election + reconnect), and the surviving members report the same
digest. Restart the killed member and it catches up to the same digest.

## Snapshots and ClusterTool

Snapshots run hourly on the leader (`snapshot.interval`). Manually:

```bash
java -jar distribution/target/radiusward.jar cluster-tool .local/data/node-0/cluster describe
java -jar distribution/target/radiusward.jar cluster-tool .local/data/node-0/cluster snapshot
```

The log is not purged yet ([ADR 0014](../adr/0014-log-purge.md)); `scripts/run-local.sh clean` starts over.

## Known local caveats

- macOS `fsync` does not flush the drive cache: durability under power loss is tested on Linux (Phase 2).
- After `kill -9` a member can only restart once its archive and cluster mark files are older than 10 s
  (Aeron's liveness check); the launcher waits and retries for up to 20 s.
- Latency locally is ~20 ms p50: the small profile's agents sleep 1 ms when idle and every commit is fsynced.
