# linux-tests

Fault injection in Linux containers with Testcontainers ([ADR 0016](../../docs/adr/0016-fault-injection-tests.md)).
Uses the release image `radiusward:dev`, a test image `radiusward-test:dev` for the members (LazyFS,
iptables; [docker/Dockerfile.test](docker/Dockerfile.test)) and the configuration files of `deploy/compose`.

```bash
scripts/linux-tests.sh                    # builds jar + images, runs everything (~15 min)
scripts/linux-tests.sh PowerLossIT        # one class
SKIP_BUILD=1 scripts/linux-tests.sh ...   # reuse the images
```

| Test | Scenario | Proves |
|---|---|---|
| `PowerLossIT` | data on LazyFS; all three members lose power under load | fsync level 2: every acknowledged event survives; level 0 (control) loses them |
| `PartitionIT` | leader cut off from both followers (iptables) | minority never acknowledges; old leader rejoins as follower; nothing lost |
| `DiskFullIT` | leader's data directory (tmpfs) filled under load | not ready below `cluster.disk.min.free`; full disk stops the member; replacement catches up; nothing lost |
| `OverloadIT` | 2M sessions, 48k requests/s offered, 1 GiB members, 384 MiB gateways | no OOM kill, memory below the limits, gateways shed load, consistent afterwards |
| `FailoverTimingIT` | leader `kill -9` at ~2k requests/s | 0 retransmissions, worst ACK < 3 s |
| `ComposeSmokeIT` | the shipped `deploy/compose` stack | healthy, both gateways acknowledge |

`ContainerCluster` is the harness: static addresses, `kill`, `restart`, `powerLoss`, `isolate`/`heal`,
`memory` (cgroup), `state`, `load`, `verifyAcks`. Clients run in a tools container inside the network.
Container logs end up in `target/container-logs/<test>/`.

Needs privileged containers and `/dev/fuse` (Linux, Colima, GitHub runners). The compose stack uses the same
subnet; stop it first.
