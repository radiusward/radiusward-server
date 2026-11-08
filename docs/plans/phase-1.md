# Phase 1 build plan: replicated accounting, running locally

Status: **done** (2026-11-08) · Created: 2026-11-08 · Builds on: [Phase 0](phase-0.md) · Report: [below](#phase-1-report)

## Goal

Phase 1 delivers the first working version: a 3-node Aeron Cluster plus 2 gateways, running **locally on
macOS without Docker** (ADR 0009). The NAS gets an Accounting-Response only after the record is
committed and fsynced on a majority, and duplicates are never applied twice.

## Exit criteria

1. `./mvnw verify` passes. `./mvnw -Pe2e verify` passes against **separate JVM processes**.
2. **ACK only after commit:** with two of three nodes down, nothing gets acknowledged. Once a majority
   is back, retries are acknowledged and each event is applied exactly once.
3. **`kill -9` of the leader under load** (about 2k requests/s, 1,000 sessions): every acknowledged event
   is in the cluster state, no event is applied twice, and the state of all three nodes is identical.
4. **Duplicates:** an identical retransmit is answered from the gateway cache. A retransmit with a new
   Identifier or Acct-Delay-Time, or one sent through the other gateway, is recognised by the cluster and
   not applied again.
5. **Restarts:** a restarted node catches up from snapshot plus log. After a snapshot and a full restart,
   duplicates are still recognised.
6. **No allocation per packet** in the gateway hot path (including a path that logs) or in the cluster
   service in steady state, enforced by tests. One known JDK exception (P1.6).
7. **Memory:** about 80 bytes per session or less, measured. Nodes run with `-Xmx384m` (small profile).
8. **Three ways to run it:** an in-JVM test harness, dev mode in IntelliJ, and `scripts/run-local.sh`,
   including the leader-kill demo.
9. **Docs:** new ADRs, a README for each new module, an updated contributor guide (`CONTRIBUTING.md`, `AGENTS.md`), failure matrix, and a local
   cluster operations guide.

## Confirmed decisions (2026-11-08)

| # | Decision |
|---|---|
| 1 | **Config:** properties files with environment variable overrides (`RADIUSWARD_*`, `${env:VAR}` for secrets), no extra library |
| 2 | **Logging:** **Log4j2 async loggers backed by the LMAX Disruptor**; logging **never blocks** the producing thread (custom always-discard queue-full policy + dropped-events counter); garbage-free mode; Log4j2 API directly |
| 3 | **Health and `/state` endpoint** on the JDK's built-in HTTP server (`com.sun.net.httpserver`), already in Phase 1 |
| 4 | **Packaging:** one `radiusward.jar` with subcommands (`cluster-node`, `gateway`) — the single container image in Phase 2 |
| 5 | **Load generator:** `radclient load` in Phase 1 |
| 6 | **Log purge:** spike in Phase 1, implementation in Phase 3 with the sink checkpoints |

Facts checked against Aeron 1.54.0 source: member string format
`id,ingress:port,consensus:port,log:port,catchup:port,archive:port|…`; `ClusteredService` callbacks
(`onStart(cluster, snapshotImage)`, `onSessionMessage`, `onTimerEvent`, `onTakeSnapshot`, `onRoleChange`,
`onNewLeadershipTermEvent`); snapshots via `ClusterControl.ToggleState.SNAPSHOT` / `ClusterTool snapshot`;
fsync via `aeron.archive.file.sync.level` and `aeron.archive.catalog.file.sync.level`. **Open-source Aeron
has no log purge** (`ClusterTool` has no purge command; the cluster never deletes archive segments).
SBE 1.42.0 is used at build time only, so its Agrona 2.7.1 dependency does not clash with Aeron's 2.7.0.

## New modules

```text
radiusward/
├── protocol/              # SBE schema + generated codecs (sbe-tool at generate-sources)
├── common/                # config (properties + env), Aeron context factory, profiles, idle strategies,
│                          # health server, Log4j2 setup + non-blocking queue-full policy
├── cluster-service/       # AccountingService, SessionStore, dedup, snapshots (deterministic, no I/O)
├── cluster-node/          # launcher: ClusteredMediaDriver + ServiceContainer, snapshot scheduler, health
├── gateway/               # UdpAgent, ClusterClientAgent, NAS registry, response cache, EventKeyStrategy
├── distribution/          # one radiusward.jar: `radiusward cluster-node | gateway`
├── testing/
│   ├── test-harness/      # LocalCluster (in-JVM), DevCluster main, cluster integration tests
│   └── e2e-tests/         # -Pe2e: ProcessLauncher, real UDP, kill -9 scenarios
├── tools/radclient/       # + `load` subcommand (load generator with ack log)
└── scripts/run-local.sh   # start|stop|status|kill <x>|restart <x>|logs <x>|demo-failover
```

New dependencies: Aeron 1.54.0 (`aeron-cluster`, `aeron-archive`, `aeron-driver`, `aeron-client`),
`log4j-api` + `log4j-core` 2.26.1 (via `log4j-bom`), `com.lmax:disruptor` 3.4.4 (the version Log4j is
built and tested with); `sbe-tool` 1.42.0 at build time only.

## Work steps

### P1.1: Protocol module, SBE (size M)

- Schema `protocol/src/main/resources/radiusward-schema.xml` (id 1, version 1), package
  `io.radiusward.protocol`. Codecs generated by `sbe-tool` at `generate-sources`, like the dictionary code.
- **Messages:**

  | Message | Fields (core) |
  |---|---|
  | `AccountingCommand` | correlationId, gatewayId, nasId, sessionKey (128 bit), exactKey (128 bit), statusType, sessionTime, eventTimestamp, inputOctets64, outputOctets64, sessionId (var), rawAttributes (var) |
  | `AccountingCommitted` | correlationId, outcome (APPLIED / DUPLICATE / STALE), eventId (= log position) |
  | `AccountingRejected` | correlationId, reason (CAPACITY, …) |
  | `SessionQuery` / `SessionReport` | admin and test: the state of one session |
  | `StateQuery` / `StateReport` | applied, duplicates, active sessions, state digest |
  | Snapshot: `SnapshotHeader`, `SessionChunk` (repeating group), `ExactKeyChunk`, `SnapshotFooter` | streamed in chunks |

- Every field has a `sinceVersion`; append-only rules as in ADR 0005.
- ✅ **Done when:** round-trip tests for every message, and a test that a v1 decoder reads a v2 message.

### P1.2: `common` (size M)

- **Config:** `radiusward.properties` per component; every key can be overridden by an environment
  variable (`RADIUSWARD_NODE_ID`), `${env:VAR}` for secrets; typed accessors with errors naming the key.
- **Profiles** `small | standard | large` set Aeron term lengths, threading mode, idle strategy and the
  logging ring size (ADR 0004).
- **`AeronContexts` factory:** MediaDriver, Archive (`fileSyncLevel=2`, `catalogFileSyncLevel=2`),
  ConsensusModule, cluster client — all from config; macOS socket buffer sizes adjusted automatically.
- **Management HTTP server** — the JDK's built-in `com.sun.net.httpserver.HttpServer` (module
  `jdk.httpserver`, supported exported API since Java 6), **no dependency**. One small management port per
  process, separate from RADIUS traffic:

  | Endpoint | Cluster node | Gateway | Kubernetes (Phase 4) |
  |---|---|---|---|
  | `/health` | process alive, Aeron agents running, no fatal error | process alive, UdpAgent + ClusterClientAgent running | `livenessProbe` |
  | `/ready` | cluster member, leader known, archive up | UDP socket bound **and** connected to the cluster leader | `readinessProbe` — LB sends RADIUS only to ready gateways |
  | `/state` | JSON: role, leaderId, term, commitPosition, applied, duplicates, activeSessions, stateDigest, dropped log events | JSON: pending, ring-buffer fill, response-cache size, packets accepted / dropped / unauthentic, dropped log events | debugging; used by the Phase 1 e2e tests |
  | `/metrics` (Phase 3) | same numbers, Prometheus text format | same | Prometheus scraping |

  Example node `/state`:

  ```json
  {"component":"cluster-node","nodeId":1,"role":"LEADER","leaderId":1,"term":4,
   "commitPosition":18874368,"applied":120344,"duplicates":512,"activeSessions":4980,
   "stateDigest":"9f2c41d07a3b55e1","log":{"dropped":0}}
  ```

  **Off the hot path:** agent threads and the cluster service only increment counters — **Aeron counters**
  in the CnC file (also visible with `AeronStat`) or plain fields written with ordered stores. They never
  call into the HTTP server or take a lock for it. The HTTP thread only reads those counters (plus
  Aeron's own: cluster role, commit position), builds JSON by hand with a `StringBuilder` (no JSON library)
  and answers; allocation there is fine. **One HTTP worker thread** (`Executors.newSingleThreadExecutor`)
  so probes and scrapes cannot take CPU from the agents.

  Config:

  ```properties
  management.http.enabled=true
  management.http.host=127.0.0.1     # 0.0.0.0 inside a pod, never exposed through the RADIUS Service
  management.http.port=9090          # locally: node i -> 9090+i, gateways 9190, 9191
  ```

  Security: no authentication in Phase 1; `/state` contains no secrets (no shared secrets, no user names);
  bound to `127.0.0.1` locally, pod network only in Kubernetes (NetworkPolicy later); no write or debug
  endpoints — snapshots etc. go through `ClusterTool`. Not chosen: Jetty/Undertow (dependency and threads
  for a few tiny GETs), Netty-based servers (Netty banned), Micrometer (maybe reconsidered for `/metrics` in
  Phase 3). HTTP/1.1 only and basic threading are fine for probes and scrapes.
- **Logging — Log4j2 async loggers + LMAX Disruptor, never blocking:**

  | Setting | Value | Why |
  |---|---|---|
  | Context selector | `AsyncLoggerContextSelector` (all loggers async) | every log call goes through the Disruptor ring buffer |
  | Ring buffer full | custom **`NonBlockingQueueFullPolicy`**: always DISCARD, count it | Log4j's default blocks the logging thread; its discard policy still blocks for WARN/ERROR |
  | Dropped-events counter | in `/state` (Prometheus metric in Phase 3) | lost log lines are visible |
  | Ring buffer size | small 8192 · standard 65536 · large 262144 | the 262,144-slot default preallocates tens of MB |
  | Wait strategy | `Timeout` (default) | idle background thread uses no CPU |
  | Appenders | RollingRandomAccessFile with `immediateFlush=false`; console in dev | batched writes on the background thread |
  | Garbage-free | `log4j2.enableThreadlocals=true`, `log4j2.enableDirectEncoders=true`, garbage-free PatternLayout | no allocation per log call |

  Rules: Log4j2 API directly (no SLF4J); parameterized messages only, `Unbox.box(long)` for primitives,
  no concatenation or lambdas; **no per-packet logging on the hot path** (counters instead; DEBUG guarded
  by `isDebugEnabled()`; repeated warnings rate-limited, e.g. one line per NAS per minute with a count).
  Config in `common`: `log4j2.xml` + `log4j2.component.properties`.
- ✅ **Done when:** config/override unit tests; profiles produce the expected contexts; a test fills the
  logging ring and proves the producer is never blocked and drops are counted; management server tests
  (status codes for healthy/unhealthy/not-ready, JSON shape, counters read without blocking writers).

### P1.3: `cluster-service`: SessionStore and dedup (size L) — the core of Phase 1

- **SessionStore:** sessions as columns of primitive arrays, grown in chunks — no object per session,
  allocation only on growth, ~70–80 bytes per session.
  - Index: `Long2LongHashMap` from the first 64 bits of `sessionKey` to a slot; the second 64 bits are
    checked in the slot.
  - Columns: key hi/lo, nasId, state (ACTIVE / STOPPED), last statusType, sessionTime, eventTimestamp,
    input/output octets, startExactKey hash, lastSeen (cluster time), tombstoneUntil, per-NAS list
    (prev/next).
- **Dedup rules** (cluster time only):

  | Event | Rule |
  |---|---|
  | Start | ACTIVE with the same start key → DUPLICATE; STOPPED with expired tombstone, or no session → APPLIED (new) |
  | Interim | progress `(sessionTime, octets total, eventTimestamp)` equal → DUPLICATE, older → STALE, newer → APPLIED; no known Start → session created implicitly |
  | Stop | already STOPPED → DUPLICATE; otherwise APPLIED + tombstone (default 1 h) |
  | Accounting-On / Off | exact-key window (default 15 min); on APPLIED every active session of that NAS is stopped (per-NAS list) |

- **Exact-key window:** ring + hash of `exactKey → expiry` for events without a monotonic field.
- **Housekeeping:** cluster timer every 60 s removes expired tombstones and **idle sessions** (no update
  for longer than `idleTimeout`, default 2 h — protects against lost Stops); sweep in fixed slot order.
- **Capacity:** `maxSessions` from the profile (small: 2M); when full, a new Start gets
  `AccountingRejected(CAPACITY)`, no ACK, alert.
- **eventId** = log position of the applied command (unique, deterministic; used by sinks in Phase 3).
- **State digest:** running hash over every applied change, identical on every replica.
- **Snapshot:** `onTakeSnapshot` streams the store in chunks of ~1,000 sessions; `onStart` rebuilds it;
  the active version (ADR 0005) is part of the snapshot.
- ✅ **Done when:** unit tests for every rule; jqwik property (any order of the same events, with
  duplicates, gives the same final state); snapshot round-trip; replay test (same command stream into two
  fresh instances → identical digest); 500k sessions ≤ 45 MB; 1M commands in steady state allocation-free.

### P1.4: `cluster-node` launcher (size M)

- `ClusterNodeMain`: config → `ClusteredMediaDriver.launch(...)` + `ClusteredServiceContainer.launch(AccountingService)`.
- **Member string and ports** from `cluster.members=host0,host1,host2` and `cluster.basePort`; locally node
  *i* uses `9000 + 100·i + {ingress 0, consensus 1, log 2, catchup 3, archive 4, archive replication 5}`.
- **Directories:** `${dataDir}/node-i/{aeron,archive,cluster}`; on macOS the Aeron directory goes in the
  temp directory.
- **Snapshot scheduler:** leader only, toggles `ClusterControl.SNAPSHOT` every `snapshot.interval`
  (default 1 h); manual snapshots via `ClusterTool snapshot` (wrapped in `scripts/cluster-tool.sh`).
- **Log purge: spike only** — how to delete archive segments below a snapshot position with
  `AeronArchive.purgeSegments` and the RecordingLog. Implemented in Phase 3; in Phase 1 the log grows
  (documented).
- SIGTERM shuts down cleanly; `kill -9` is part of the tests.
- ✅ **Done when:** 3 nodes start locally, elect a leader, `/state` shows the role.

### P1.5: Gateway: NAS registry and event keys (size M)

- **NasRegistry** from config: `nas.<name>.address` (IP or CIDR), `.secret`, `.vendor`,
  `.messageAuthenticator=required|optional|off`. IPv4 lookups allocation-free (`Int2ObjectHashMap` keyed by
  the `Inet4Address` value, whose `hashCode()` is the address) plus a CIDR list. NAS identity comes from
  config, **never from NAS-IP-Address** in the packet.
- **EventKeyStrategy:** `sessionKey` = 128-bit hash of (nasId, Acct-Session-Id); `exactKey` = hash of
  (nasId, Acct-Session-Id, statusType, sessionTime | eventTimestamp), without Acct-Delay-Time and without
  the Identifier. Hash function pinned and tested against fixed vectors. The six vendors start with the
  default strategy; vendor-specific rules only once real captures show they are needed.
- ✅ **Done when:** key tests across all 21 fixtures, including the same event with a different Identifier
  or delay time giving the same key.

### P1.6: Gateway agents (size L)

- **Pipeline** without object queues:

  ```text
  UdpAgent ──(OneToOneRingBuffer: SBE AccountingCommand bytes)──▶ ClusterClientAgent ──▶ cluster ingress
  UdpAgent ◀──(OneToOneRingBuffer: commit notifications)──────── ClusterClientAgent ◀── egress
  ```

  Agrona `OneToOneRingBuffer`s (zero-copy, allocation-free) — refines ADR 0006. (The Disruptor is used
  only inside Log4j2.)
- **UdpAgent:** receive → `RadiusPacket.wrap` → NAS lookup → verify authenticator / Message-Authenticator
  → response cache → extract → keys → command into the ring buffer.
- **Response cache** (RFC 5080): (source IP, port, Identifier, authenticator hash) → `PENDING | COMMITTED`,
  30 s expiry. The response is deterministic, so it is not stored: on a COMMITTED retransmit the gateway
  re-encodes it from the incoming packet (~32 bytes per entry). PENDING retransmits are dropped.
- **Pending table:** preallocated slab of in-flight request copies (needed to build the response),
  bounded (default 64k; full → drop), 10 s timeout. A late commit marks the cache entry COMMITTED so the
  next retransmit is answered immediately.
- **ClusterClientAgent:** `tryClaim` into the cluster without copying; **keeps polling egress while
  backpressured**; on leader change or lost connection reconnects asynchronously and **resends pending
  commands unchanged** (safe because of dedup).
- **Threading:** `gateway.threading=shared` (one thread, small profile) or `dedicated` (two threads).
- **Known JDK limitation:** `DatagramChannel.receive()` creates a new `InetSocketAddress` whenever the
  sender changes — with 1,000 NAS ~80 bytes per packet, ~1.3 MB/s at peak, harmless for the GC.
  radiusward's own code allocates nothing; the test checks exactly that boundary.
- ✅ **Done when:** component tests against a mocked cluster client (ring buffers), and `GatewayAllocationIT`.

### P1.7: `distribution` and `run-local.sh` (size S)

- One shaded `radiusward.jar` with `Main`: `radiusward cluster-node --config …`,
  `radiusward gateway --config …`; `Add-Exports` in the manifest.
- `config/local/`: `node-0..2.properties`, `gateway-a.properties` (UDP 1813), `gateway-b.properties`
  (UDP 1814), `nas-clients.properties` (127.0.0.1, `testing123`, vendor default).
- **`scripts/run-local.sh`:** `start | stop | status`, `kill <node|gateway>` (`kill -9`), `restart <x>`,
  `logs <x>`, `demo-failover` (load → kill the leader → show the result). PID and log files in `.local/`
  (git-ignored).
- ✅ **Done when:** `run-local.sh start` + `radclient acct` gives an ACK, and `demo-failover` runs end to end.

### P1.8: Test harness and dev mode (size M)

- **`LocalCluster`** (in-JVM): builder for N nodes and M gateways with temp directories and free ports;
  `awaitLeader()`, `stop(i)`, `restart(i)`, `state(i)`, `send(fixture)`.
- **Cluster integration tests** on the harness: election, commit, snapshot and restore, digest equal on
  all nodes.
- **`DevCluster` main:** 3 nodes + 2 gateways in one JVM on fixed ports; IntelliJ run configuration in `.run/`.
- ✅ **Done when:** integration tests stable (10 runs in a row, no flakes); dev mode starts in under 5 s.

### P1.9: `radclient load` (size S)

- `radclient load --server … --nas 10 --sessions 1000 --rate 2000 --duration 60s --interim 10s --ack-log acks.csv`
- Simulates Start/Interim/Stop cycles across many sessions, logs every acknowledged event, reports
  throughput and p50/p99/max latency (simple histogram, no dependency).
- ✅ **Done when:** used by the e2e tests and the failover demo.

### P1.10: End-to-end tests, `testing/e2e-tests` with `-Pe2e` (size L)

- **ProcessLauncher** starts `java -jar radiusward.jar …` as real processes on free ports, reads `/state`,
  `kill -9` via `ProcessHandle.destroyForcibly()`.

  | Test | Scenario | Checks |
  |---|---|---|
  | `AckAfterCommitIT` | stop 2 of 3 nodes → send; restart one | no ACK without a majority; ACK afterwards; applied exactly once |
  | `LeaderFailoverIT` | load at 2k/s, `kill -9` the leader at t=10 s | every acked event in state; per-session state equals the last event; digests equal |
  | `RetransmitIT` | identical retransmit; new Identifier and Acct-Delay-Time; via gateway B | cache hit without a cluster round trip; cluster DUPLICATE; state unchanged |
  | `GatewayFailoverIT` | `debug.responseDelayMs` on gateway A, kill A, retry via B | answered by B as DUPLICATE, applied once |
  | `NodeRestartIT` | kill a follower, load, restart | catches up; digest equal |
  | `SnapshotRestoreIT` | snapshot, restart all nodes, send old events again | recognised as duplicates |
  | `AccountingOnOffIT` | Accounting-On from a NAS with active sessions | its sessions are closed |
  | `VendorFixturesIT` | all 21 fixtures through the gateway | ACK for each, correct state |

- `debug.*` settings only work with `debug.enabled=true`; the node refuses to start with them in the
  production profile.
- ✅ **Done when:** all scenarios pass, `-Pe2e` passes 3 times in a row locally.

### P1.11: Documentation (size M), written alongside the code

- **New ADRs:** 0010 Configuration (properties + env, no dependency); 0011 Gateway pipeline (ring buffers,
  response cache without stored responses, pending slab); 0012 SessionStore and dedup algorithm (details
  for ADR 0003); **0013 Operational endpoints and logging (JDK HTTP server: `/health`, `/ready`, `/state`,
  later `/metrics`, counters read off the hot path; Log4j2 async loggers + LMAX Disruptor, non-blocking)**; 0014 Log purge (spike result, implementation in Phase 3).
- Updates: ADR 0006, `protocol.md` (final), README per new module, `docs/operations/local-cluster.md`
  (`run-local.sh`, dev mode, ClusterTool, failover demo), `CONTRIBUTING.md` + `AGENTS.md`, failure matrix (P1 rows ✅),
  `docs/configuration.md` (every key with its default), `THIRD-PARTY-LICENSES.md` (Aeron, Log4j2, Disruptor
  — all Apache-2.0).
- ✅ **Done when:** all links check out and the Phase 1 report is appended to this file.

### P1.12: Phase review (size S)

- Check the exit criteria, record latencies (p50/p99 ACK time locally) and memory per session, plan Phase 2.

## Order

```text
P1.1 protocol ─┬─▶ P1.3 cluster-service ─▶ P1.4 cluster-node ─┐
P1.2 common ───┤                                               ├─▶ P1.7 distribution ─▶ P1.8 harness/dev ─▶ P1.10 e2e ─▶ P1.12
               └─▶ P1.5 registry/keys ─▶ P1.6 gateway agents ──┘          ▲
                                                    P1.9 radclient load ───┘
P1.11 docs alongside: ADR 0010–0013 before the code, the rest with each step
```

P1.3 and P1.5/P1.6 can be built in parallel; they only share the protocol.

## Risks

| Risk | Handling |
|---|---|
| Elections make the tests flaky | generous wait helpers (`await(…, 20s)`), 10 runs in a row as an exit criterion, test reports in CI |
| Hidden non-determinism in the service | replay test, digest comparison across 3 nodes in every e2e test, determinism rules in `CONTRIBUTING.md` |
| Small macOS UDP buffers or port collisions | lower socket buffers in the local profile, free-port detection in the harness |
| Log4j2 garbage-free mode misconfigured | `HotPathAllocationIT` covers a logging path; ring-full test proves non-blocking |
| Purge spike shows it is harder than expected | fine for Phase 1 (log grows); decide in Phase 3 between purge and the fallback backlog |
| `kill -9` cannot be simulated in-JVM | real processes in e2e (that is why `-Pe2e` exists) |
| Gaps in Aeron knowledge (catchup, session timeouts) | settings explicit in `AeronContexts`, documented with sources |

## Still open

- Commit Phase 0 before starting Phase 1.
- 61 of 64 extractor fields are used; widen the presence mask (two longs) before adding more.

---

## Phase 1 report

Completed 2026-11-08. `./mvnw clean verify` (JDK 21): **BUILD SUCCESS, 251 tests, 1 skipped** (FreeRADIUS
interop, `radiusd` not installed). `./mvnw -Pe2e verify`: **8/8 e2e scenarios, 3 runs in a row** (~175 s
each). In-JVM integration tests: 10+ consecutive green runs.

### Exit criteria

| # | Criterion | Result |
|---|---|---|
| 1 | `verify` and `-Pe2e verify` green | ✅ both; e2e 3× in a row |
| 2 | ACK only after commit | ✅ `AckAfterCommitIT`: with 2 of 3 members down nothing is acknowledged; after recovery the retransmit is acknowledged and applied once |
| 3 | `kill -9` of the leader under ~2k req/s | ✅ local processes: 70,000 events at 2,057 req/s, **70,000 acknowledged, 0 failed**, 10,000 sessions ended STOPPED on both survivors, identical digests. `LeaderFailoverIT` additionally checks every session's state against the ack log |
| 4 | Duplicates | ✅ cache hit for identical retransmits; new Identifier / Acct-Delay-Time / other gateway → cluster duplicate (`RetransmitIT`, `GatewayFailoverIT`) |
| 5 | Restarts | ✅ follower restart right after `kill -9` (`NodeRestartIT`); snapshot + full restart keeps dedup (`SnapshotRestoreIT`) |
| 6 | No allocation per packet | ✅ gateway (100k packets < 64 KB incl. the test client), state machine (2M commands < 4 KB), logging (100k calls < 64 KB). JDK caveat: sender address allocation when the sender changes |
| 7 | ≤ ~80 bytes per session, `-Xmx384m` | ✅ ~77 bytes (500k sessions ≈ 38 MB, asserted ≤ 45 MB); nodes run with `-Xmx384m` in `run-local.sh` and the e2e tests |
| 8 | Three ways to run | ✅ `LocalCluster`, `DevCluster` (ready in 885 ms), `scripts/run-local.sh` incl. `demo-failover` |
| 9 | Docs | ✅ ADR 0010–0014, configuration reference, local-cluster guide, protocol (final), module READMEs, contributor guide, failure matrix; links checked |

### Measurements (Apple M4 Pro, JDK 21, small profile, fsync level 2, all on one machine)

| | |
|---|---|
| ACK latency, steady | p50 ~18–20 ms, p99 ~30–45 ms |
| Failover (`kill -9` leader, 3 s heartbeat timeout) | ~6 s outage; every event acknowledged after NAS retransmission |
| Throughput tested | 2,057 req/s sustained through 2 gateways during failover |
| Session state | ~77 bytes per session |
| Dev mode startup | 885 ms |

Latency is dominated by the small profile's 1 ms sleeping idle strategy in several agents and the fsync per
commit; it is far below NAS timeouts (3–5 s) and will be profiled on Linux in Phase 2.

### Deviations from the plan

| Plan | What was done | Why |
|---|---|---|
| Gateway resends pending commands after a reconnect | A retransmit of a request pending > 1 s is resubmitted (`gateway.retransmit.resubmit.after`) | Found by the failover demo: 846 of 7,000 events failed because the gateway swallowed retransmits of commands lost with the dead leader. Resubmission on retransmit needs no stored command bytes; afterwards 0 failures |
| — | Launcher retries for up to 20 s on "active mark file detected" | Aeron's archive/cluster mark files count as alive for a fixed 10 s; without this a member cannot restart right after `kill -9` (systemd/Kubernetes would crash-loop) |
| `scripts/cluster-tool.sh` | `radiusward cluster-tool …` subcommand | `java -cp` does not apply the jar's `Add-Exports`; the subcommand does |
| Interim progress compared field by field when both carry it | A value only the incoming event carries counts as 0 on the stored side | Found by the smoke test: the first Interim after a Start (same second, no traffic) was taken for a duplicate |
| Garbage-free Log4j2 via thread-locals and direct encoders | Also `log4j2.clock=SystemMillisClock` | JFR showed the default clock allocates a `java.time.Instant` per event (~140 → ~0.5 bytes per call) |
| Stats as Aeron counters | `AtomicLongArray` with release stores | Simpler, same non-blocking property; Aeron counters can come with `/metrics` in Phase 3 |

### Findings worth knowing

- Aeron's default leader heartbeat timeout (10 s) would make failover take ~13 s; the local profile uses
  3 s. The production default needs a decision in Phase 2 together with real NAS retry settings.
- Followers never receive `onRoleChange` at start; the role is read in `onStart`.
- Out-of-order delivery after a failover turns some older Interims into STALE — correct, their progress is
  already reflected.
- IPv6 NAS source addresses are not supported yet (IPv4 exact and CIDR are).
- All six vendors use the default event-key strategy; vendor rules wait for real captures.

### Open items for Phase 2

- Container image from `radiusward.jar`, docker-compose; Linux runs for real fsync / power-loss, quorum
  loss by partition, disk full, overload with `--memory=1g`.
- Production default for `cluster.leader.heartbeat.timeout`; latency profiling on Linux.
- Replace synthetic vendor fixtures with anonymised captures.
- GitHub owner for the GHCR image path (already known: `radiusward/radiusward-server`).
