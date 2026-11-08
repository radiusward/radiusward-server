# Phase 2 build plan: containers, Linux durability, production defaults

Status: **planned** (not started) · Created: 2026-11-08 · Builds on: [Phase 1](phase-1.md)

## Goal

radiusward runs as a container image, and what macOS could not prove is tested on Linux: real fsync, power
loss, network partitions, a full disk and overload within 1 GiB. Failover becomes fast enough that a NAS
never needs to retransmit.

## Exit criteria

1. **Compose:** `docker compose up` brings 3 nodes + 2 gateways to ready; a radclient container gets ACKs;
   the failover demo runs in compose.
2. **Release:** a `v*` tag publishes a multi-arch image (amd64 + arm64) to
   `ghcr.io/radiusward/radiusward-server`, plus release jars, an SBOM and build provenance.
3. **Failover:** `kill -9` of the leader at ~2k req/s → cluster writable again within **≤ 2.5 s** (measured
   on Linux), and **no request needs a second attempt** with a 3 s client timeout.
4. **Power loss of all three nodes** at once with fsync level 2: **0 acknowledged events lost**. A control
   run with fsync off must show losses, proving the test can detect them.
5. **Network partition:** a leader cut off on the minority side never acknowledges; the majority carries on;
   after healing everything converges with no acknowledged event lost.
6. **Full disk:** nothing acknowledged that was not durably written; recovery once space is freed (exact
   behaviour pinned down by a spike first).
7. **Overload within 1 GiB per node:** no out-of-memory kill, memory bounded, excess traffic dropped and
   counted, consistent state afterwards.
8. **CI:** build and tests (Java 21 and 25) plus e2e on every push; the Linux fault tests nightly, manually
   and on release tags — green.
9. **Docs:** ADRs, Docker and release guides, configuration, failure matrix.

## Confirmed decisions (2026-11-08)

| # | Decision |
|---|---|
| 1 | Local container engine: **Colima** (installed and running: Docker 27.4, arm64, 8 CPU / 12 GiB, cgroup v2, `/dev/fuse` available) |
| 2 | **Testcontainers** (MIT, test-only) for the Linux fault tests |
| 3 | Base image **`eclipse-temurin:25-jre-noble`** (Java 25 runtime, glibc; jar still compiled for Java 21) |
| 4 | **Multi-arch** images: linux/amd64 + linux/arm64 |
| 5 | Image tags: `<version>` and `latest` on `v*` tags; **`:edge`** on every push to `main` |
| 6 | Linux fault tests in CI: **nightly, manual and on release tags** (not on every push) |
| 7 | **One image:** radclient included as `radiusward radclient` |
| 8 | Faster failover (below) |

Local tooling notes: compose is the standalone `docker-compose` 2.32.4 (not yet linked as the `docker compose`
plugin) and `docker buildx` is not installed; multi-arch builds happen in CI, local builds are arm64.

## New and changed parts

```text
deploy/docker/Dockerfile          # image built from radiusward.jar
deploy/docker/entrypoint.sh       # profile → JVM flags, exec radiusward
deploy/compose/compose.yaml       # 3 nodes + 2 gateways (+ "tools" profile with radclient)
deploy/compose/compose.{standard,large}.yaml, deploy/compose/config/
testing/linux-tests/              # -Plinux: Testcontainers fault-injection tests
.github/workflows/ci.yml          # + e2e job
.github/workflows/linux-tests.yml # nightly / manual / on release tags
.github/workflows/release.yml     # tag v* → images + GitHub release; main → :edge
distribution: new subcommands `radclient` and `probe`
```

## Work steps

### P2.1: Container image (size M)

- Base `eclipse-temurin:25-jre-noble`; non-root user (uid 10001); jar in `/opt/radiusward`, config in
  `/etc/radiusward` (incl. `dictionary.d/`), data volume `/var/lib/radiusward`, Aeron directory in `/dev/shm`.
- Entrypoint maps `RADIUSWARD_PROFILE` to JVM flags (small → `-Xmx384m -XX:MaxMetaspaceSize=96m …`),
  `JAVA_OPTS` can add or override, then `exec java -jar radiusward.jar "$@"`.
- New subcommands: `radiusward radclient …` (the same image is the test client) and `radiusward probe <url>`
  (tiny JDK HTTP check for the container health check; the JRE image has no curl).
- Exposes 1813/udp and the management port; OCI labels.
- ✅ **Done when:** `docker run … version` works, a node and a gateway start from the image, image ≤ ~250 MB.

### P2.2: Docker Compose (size M)

- `node-0..2`: `shm_size: 512m`, `mem_limit: 1g`, `cpus: 1`, one volume each, health check on `/ready`.
  `gateway-a/b`: `mem_limit: 384m`. Fixed subnet `172.28.0.0/24`.
- Config files mounted; `cluster.members=node-0,node-1,node-2`; `gateway.egress.host` = the container's own
  name; NAS client = the compose network's CIDR, secret from an environment variable.
- `tools` profile with a radclient container on the same network. Test clients run **inside** the network:
  on macOS Docker rewrites the source IP of UDP traffic through published ports, so the gateway would not
  recognise the NAS (on Linux published ports keep it — documented as a deployment caveat).
- `compose.standard.yaml` / `compose.large.yaml` profile overrides; failover demo with
  `docker kill -s KILL` on the leader container.
- ✅ **Done when:** `docker compose up -d` → all healthy; `docker compose run tools radclient acct …` → ACK;
  the compose failover demo loses no events.

### P2.3: Faster failover (size M) — decided 2026-11-08

**Measured in Phase 1** (`kill -9` of the leader at ~2k req/s, local processes, M4 Pro):

| Step | Time |
|---|---|
| detection (leader heartbeat timeout, configured 3 s) | 3.0 s |
| election | 1.1 s |
| gateways redirected to the new leader | 0.1 s |
| **cluster writable again** | **≈ 4.2 s** |

Clients saw p99 ≈ 6.0 s: a request sent just after the kill is lost with the dead leader, the NAS-like
client retransmits after 3 s (cluster not back yet) and again after 6 s (succeeds). With Aeron's default 10 s
heartbeat timeout a failover would take ~11–12 s, ~12–15 s as seen by a NAS — too close to typical NAS
give-up times (3–5 s × 3 attempts).

| # | Change | Expected effect |
|---|---|---|
| 1 | Default `cluster.leader.heartbeat.timeout` **1.5 s** (compose, dedicated hosts); **2.5 s** in the Kubernetes Helm values (Phase 4). Configurable. Heartbeat interval stays at Aeron's 200 ms (5–7 missed heartbeats before an election) | detection 3 s → 1.5 s |
| 2 | **`cluster.election.timeout` = 0.5 s** (new key → Aeron `electionTimeoutNs`) | election 1.1 s → ~0.5–0.6 s |
| 3 | Gateway **resubmits all pending requests on `onNewLeader`**; each pending slot keeps its encoded command (~1 KiB slots, ~16 MiB per gateway in the small profile; larger commands fall back to NAS retransmission). Resubmit-on-retransmit (ADR 0011) stays as fallback | removes up to one NAS retry interval (3–5 s) |
| 4 | Assertion in local e2e and Linux tests: during a leader `kill -9` under load **no request needs more than one attempt** with a 3 s client timeout | guards the target |

**Target:** writable again ~2–2.5 s after a leader crash, below a typical 3 s NAS timeout — the NAS sees one
slower answer and never retransmits. Risks: false elections from GC pauses, slow disks or network jitter at
the shorter timeouts (tested in P2.4), and the gateway memory for stored commands.

- ✅ **Done when:** the failover e2e test shows `retransmissions == 0` with a 3 s client timeout; the
  breakdown is measured on Linux; ADR 0011 amended.

### P2.4: Linux fault tests, `testing/linux-tests` with `-Plinux` (size L) — the core of Phase 2

- Testcontainers harness `ContainerCluster`: network, 3 nodes, 2 gateways, client container; helpers
  `kill`, `pause`, `isolate` (iptables, NET_ADMIN), `powerLoss`, `stats` (memory, OOM flag).
- **Power loss with LazyFS** (FUSE filesystem used by Jepsen for exactly this): writes not fsynced live only in
  its memory; "clear cache" discards them — what a power cut does. Archive directories on LazyFS mounts in
  privileged containers with `/dev/fuse`.

| Test | Scenario | Checks |
|---|---|---|
| `PowerLossIT` | load → stop all 3 nodes at once and clear the LazyFS caches → restart | fsync level 2: **every acknowledged event is in the state**. Control run with fsync level 0 must show losses |
| `PartitionIT` | cut the leader off from both followers (iptables) | minority side never ACKs; majority elects a new leader, gateways reconnect; after healing the old leader rejoins as follower, digests equal, no acknowledged event lost |
| `DiskFullIT` | archive on a size-limited tmpfs, fill it | **spike first**; expected: no ACK without a durable write, clear error in log and `/state`, recovery after space is freed or the node replaced |
| `OverloadIT` | nodes `mem_limit=1g`, gateways 384 MiB; 2M sessions; ~3× sustainable rate for 2 min | not OOM-killed (`State.OOMKilled=false`), memory + `/dev/shm` under the limit, gateways count drops, consistent afterwards |
| `FailoverTimingIT` | leader `kill -9` at ~2k req/s in containers | writable again ≤ 2.5 s, 0 retransmissions |
| `ComposeSmokeIT` | starts `deploy/compose` itself | the shipped compose file works |

- ✅ **Done when:** all green locally (Colima VM) and in the nightly CI job; `PowerLossIT`'s control run detects
  losses.

### P2.5: Latency on Linux (size S)

- Measure p50/p99 in compose for fsync levels 0/1/2 and idle strategies: the current 1 ms sleep vs
  `BackoffIdleStrategy` with ≤ 100 µs parking; trade CPU against latency for the small profile default.
- ✅ **Done when:** a measured table is in `docs/testing/strategy.md` and `architecture.md` and the defaults
  are chosen from it.

### P2.6: Memory profiles (size S)

- The entrypoint and compose overrides apply ADR 0004; `OverloadIT` measures heap, RSS and `/dev/shm`; profile
  values adjusted if needed.
- ✅ **Done when:** a small node at 2M sessions under load stays below 1 GiB in total, measured.

### P2.7: CI and releases (size M)

- `ci.yml`: add an e2e job (Linux, Java 21) on every push.
- `linux-tests.yml`: nightly, manual, on release tags (privileged containers, FUSE — supported on GitHub's
  Ubuntu runners).
- `release.yml` on `v*`: build with JDK 25 (bytecode Java 21) → `verify` + e2e → `docker buildx` amd64 +
  arm64 → push `ghcr.io/radiusward/radiusward-server:<version>` and `:latest` with SBOM and provenance →
  GitHub Release with `radiusward.jar` and `radclient.jar`. Every push to `main` publishes `:edge`.
- Publishing is outward-facing: everything is prepared, but the first real tag (e.g. `v0.2.0-rc.1`) is only
  pushed when the maintainer says so.
- ✅ **Done when:** the agreed RC tag produces the images and the release.

### P2.8: Vendor captures (size S, needs input from the maintainer)

- `radclient decode --fixture` turns captured hex into a `.fixture`, plus an anonymisation guide and script.
- Real captures have to come from real NAS devices; until then the synthetic fixtures stay marked as such.

### P2.9: Documentation (size M)

- New ADRs: **0015** Container image and runtime layout; **0016** Fault injection and durability tests
  (LazyFS, iptables, Testcontainers).
- Updates: ADR 0011 (resubmit on new leader), ADR 0004 (measured memory, slot size), ADR 0009 (Docker from
  Phase 2); new `docs/operations/docker.md` (compose, profiles, source-IP caveat) and
  `docs/operations/release.md`; `configuration.md` (new keys), failure matrix (P2 rows), `architecture.md`
  deployment, README quickstart with compose, `CONTRIBUTING.md` / `AGENTS.md`.
- ✅ **Done when:** links checked and the Phase 2 report appended to this file.

### P2.10: Review (size S)

- Check the exit criteria; record failover breakdown, latency table, memory, power-loss results; plan Phase 3.

## Order

```text
P2.1 image ─▶ P2.2 compose ─▶ P2.4 linux-tests ─▶ P2.6 memory ─▶ P2.10
     │                ▲              ▲
     └─▶ P2.7 CI/release      P2.3 failover (independent, start first)
P2.5 latency after P2.2 · P2.8 whenever captures arrive · P2.9 alongside
```

## Risks

| Risk | Handling |
|---|---|
| Docker on macOS runs a Linux VM with its own disk and network behaviour | fault-test results count only on Linux (Colima VM locally, GitHub runners in CI) |
| LazyFS build or FUSE in CI | spike at the start of P2.4; fallback `dm-flakey` (device-mapper) or VM-level power-off |
| shorter heartbeat causes needless elections | `OverloadIT` / `DiskFullIT` run with the new defaults and count elections; fall back to 2–2.5 s |
| Aeron in containers (hostnames, `/dev/shm` size) | explicit `shm_size`; Aeron re-resolves hostnames; restart tests cover it |
| UDP source IP in Docker | test clients inside the network; documented for operators |
