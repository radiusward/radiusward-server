# linux-tests

Fault injection in Linux containers with Testcontainers ([ADR 0016](../../docs/adr/0016-fault-injection-tests.md)).
Uses the release image `radiusward:dev`, a test image `radiusward-test:dev` for the members (LazyFS,
iptables; [docker/Dockerfile.test](docker/Dockerfile.test)), a systemd image `radiusward-systemd:dev` with the
units of `deploy/systemd` ([docker/Dockerfile.systemd](docker/Dockerfile.systemd)) and the configuration files of
`deploy/compose`. In CI, *Run workflow* on `linux-tests` takes a `tests` input to run single classes.

```bash
scripts/linux-tests.sh                    # builds jar + images, runs everything (~15 min)
scripts/linux-tests.sh PowerLossIT        # one class
SKIP_BUILD=1 scripts/linux-tests.sh ...   # reuse the images
LINUX_TESTS_ARGS="-Dradiusward.outage.minutes=3 -Dradiusward.purge.minutes=8" scripts/linux-tests.sh   # shorter
```

| Test | Scenario | Proves |
|---|---|---|
| `PowerLossIT` | data on LazyFS; all three members lose power under load | fsync level 2: every acknowledged event survives; level 0 (control) loses them |
| `PartitionIT` | leader cut off from both followers (iptables) | minority never acknowledges; old leader rejoins as follower; nothing lost |
| `DiskFullIT` | leader's data directory (tmpfs) filled under load | not ready below `cluster.disk.min.free`; full disk stops the member; replacement catches up; nothing lost |
| `OverloadIT` | 2M sessions, 48k requests/s offered, 1 GiB members (exporting to PostgreSQL), 384 MiB gateways | no OOM kill, memory below the limits, gateways shed load, consistent afterwards |
| `FailoverTimingIT` | leader `kill -9` at ~2k requests/s | 0 retransmissions, worst ACK < 3 s |
| `ComposeSmokeIT` | the shipped `deploy/compose` stack | healthy, both gateways acknowledge, `/metrics` |
| `MonitoringConfigIT` | `promtool` on `deploy/monitoring` | alert rules and scrape config valid |
| `PostgresOutageIT` | PostgreSQL down under load (`radiusward.outage.minutes`, default 30) | ACKs continue, backlog drains, every acknowledged session in the database |
| `ExportLagBlockIT` | required sink, `maxLag` 30 s, PostgreSQL down | `EXPORT_LAG` stops ACKs, they resume after catch-up, nothing acknowledged missing |
| `DetachIT` | optional sink, `maxLag` 20 s | detached without blocking ACKs, re-attaches, the lease stays put |
| `ExportThroughputIT` | backlog drain per storage variant | faster than intake; rows/s and bytes per row |
| `PurgeIT` | steady load (`radiusward.purge.minutes`, default 60), snapshots every minute | archive bounded, nothing acknowledged missing |
| `SystemdFailoverIT` | systemd as PID 1, the shipped units: leader's member SIGKILLed, a follower stopped and started, a gateway reloaded, another stopped (drain) | `Restart=on-failure` brings the member back, a stop ends `inactive`, the draining gateway is not ready, nothing acknowledged missing, every unit `active` again |

`ContainerCluster` is the harness: static addresses, `kill`, `restart`, `powerLoss`, `isolate`/`heal`,
`memory` (cgroup), `state`, `load`, `verifyAcks`; with `Options.systemd(true)` the containers boot systemd and the
harness enables the units (`systemctl`, `unitState`, `unitRestarts`; logs from the journal). Clients run in a tools container inside the network.
Container logs end up in `target/container-logs/<test>/`.

Needs privileged containers and `/dev/fuse` (Linux, Colima, GitHub runners). The compose stack uses the same
subnet; stop it first.
