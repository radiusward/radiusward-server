# e2e-tests

End-to-end tests against separately started `java -jar radiusward.jar` processes (3 members, 2 gateways,
free ports, real `kill -9`). Only built with the `e2e` profile:

```bash
./mvnw -Pe2e verify
```

Ports are chosen below the ephemeral ranges (cluster 20000–32205, management and RADIUS 10000–19999): a port
taken from the ephemeral range and checked free could be reused by another process's client socket before the
member binds it. A member that does not become ready or a missing leader fails with the last lines of the process
logs in the message, since the temp directory is not kept in CI.

| Test | Scenario |
|---|---|
| `AckAfterCommitIT` | no ACK without a majority; after recovery the retransmit is acknowledged and applied once |
| `LeaderFailoverIT` | `kill -9` of the leader under 2 gateways' load: every acked event is in the replicated state |
| `RetransmitIT` | gateway cache hit; new Identifier + Acct-Delay-Time via the other gateway is a cluster duplicate |
| `GatewayFailoverIT` | gateway dies after commit (debug response delay); retry via the other gateway is a duplicate |
| `NodeRestartIT` | follower killed with -9 restarts right away and catches up |
| `SnapshotRestoreIT` | `cluster-tool snapshot`, restart all members, old events are still duplicates |
| `AccountingOnOffIT` | Accounting-On closes the NAS's sessions |
| `RollingUpgradeIT` | members restarted one by one with a release knowing a newer state version: activated automatically when the last one runs it, same digest everywhere; a member rolled back afterwards stops |
| `DevicesBehindNatIT` | NAS entry with `identity = nas-identifier`: two access points with the same Acct-Session-Id are two sessions; an Accounting-On stops only the rebooted one's |
| `VendorFixturesIT` | all 21 vendor fixtures acknowledged and replicated |

Process logs of failed tests stay in their temp directory (path in the failure message).
