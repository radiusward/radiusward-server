# ADR 0016: Fault injection and durability tests in Linux containers

Status: Accepted (2026-11-08). Phase 2.

## Context
The durability promise (ADR 0002: an ACK means fsynced on a majority) and the failure behaviour cannot be
proven on macOS, where `fsync` is not power-loss durable (ADR 0009), and not with `kill -9` alone, which
leaves the page cache intact.

## Decision
`testing/linux-tests` (`-Plinux`, `scripts/linux-tests.sh`) runs the shipped image and the shipped compose
configuration in Docker via **Testcontainers**; all clients run inside the Docker network.

- **Power loss: LazyFS** (dsrhaslab/lazyfs, MIT; the FUSE filesystem Jepsen uses). The member's data
  directory lives on LazyFS, which keeps every write in its own cache until `fsync`. Killing the container
  kills LazyFS, so unsynced data is gone: a power cut of all three members at once. Built from source in the
  test image (`testing/linux-tests/docker/Dockerfile.test`, pinned commit) with one patch: upstream does not
  implement `statfs`, reports 0 bytes free, and Aeron Archive then refuses to record.
- **Negative control**: the same power loss with `archive.file.sync.level=0` must lose acknowledged events
  (measured: the catalog is zeroed and no member starts). Without it the test could pass because nothing
  was simulated.
- **Partitions** with `iptables` inside the member container (`NET_ADMIN`); **full disk** with a
  size-limited tmpfs as data directory; **overload** with memory limits from ADR 0004 and memory read from
  the container's cgroup (anon + shmem = what cannot be reclaimed).
- Verification: `radclient load --ack-log` records every acknowledged event; `radiusward admin verify-acks`
  queries the replicated state through the cluster log and fails if any acknowledged event is missing.
- Runs nightly, on demand and for release tags (`linux-tests.yml`), not on every push (~15 min).

## Consequences
- The tests found two real problems before any release:
  1. Aeron Cluster's own `fileSyncLevel` (recording log, node state) defaults to 0 and was not set: after a
     power loss `node-state.dat` was empty and no member could start. Now tied to `archive.file.sync.level`.
  2. A full disk ends in SIGBUS on a write to a memory-mapped file, so the member's JVM dies. That is
     safe (it cannot acknowledge anything it did not write, the majority continues), but gave no warning.
     Members now report not ready below `cluster.disk.min.free`.
- Results come from a Linux VM (Colima locally, GitHub runners in CI); absolute latencies there are not
  bare-metal numbers.
- Testcontainers, LazyFS, spdlog and toml11 are test-only and never part of the published image.
