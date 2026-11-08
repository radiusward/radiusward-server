# Architecture

This is the **target architecture**. What exists today is marked per section; the roadmap is in
[plans/roadmap.md](plans/roadmap.md), decisions with their reasoning in [adr/](adr).

## Context

```text
        ┌───────────────────────────── operator network ─────────────────────────────┐
        │                                                                             │
  NAS (BNG, router,      RADIUS accounting (UDP 1813)        radiusward                Downstream
  WLAN controller, AP) ─────────────────────────────────▶  ┌──────────────┐  export  ┌────────────┐
  ~1,000 devices,         Accounting-Response              │  gateways    │ ───────▶ │ Postgres   │
  ~500k concurrent    ◀───────────────────────────────────  │  cluster     │          │ Kafka, ... │
  sessions                                                  │  exporter    │          └────────────┘
                                                            └──────────────┘
        └─────────────────────────────────────────────────────────────────────────────┘
```

radiusward replaces the accounting part of a RADIUS server. Authentication and authorization come later
(Phase 5) and are out of scope here.

## Containers

```text
                     NAS devices
                          │ UDP (source IP identifies the NAS and its shared secret)
            ┌─────────────┴─────────────┐
            ▼                           ▼
   ┌─────────────────┐         ┌─────────────────┐
   │   gateway A     │         │   gateway B     │      stateless, N replicas
   │ ─────────────── │         │                 │
   │ UdpAgent        │         │                 │
   │  NIO socket     │         │                 │
   │  validate/auth  │         │                 │
   │  extract, keys  │         │                 │
   │  response cache │         │                 │
   │      │ Agrona   │         │                 │
   │      ▼ rings    │         │                 │
   │ ClusterClient   │         │                 │
   │  Agent          │         │                 │
   └────────┬────────┘         └────────┬────────┘
            └───────── aeron:udp ───────┘   ingress: AccountingCommand
                          │                 egress:  AccountingCommitted
       ┌──────────────────┼──────────────────┐
       ▼                  ▼                  ▼
 ┌───────────┐      ┌───────────┐      ┌───────────┐
 │ node 0    │◀────▶│ node 1    │◀────▶│ node 2    │   Aeron Cluster (Raft), static membership
 │ leader    │ log  │ follower  │ log  │ follower  │   each: media driver, archive (fsync),
 │           │      │           │      │           │   consensus module, AccountingService
 └─────┬─────┘      └───────────┘      └───────────┘
       │ archive replay of the committed log (on a follower)
       ▼
 ┌───────────┐   per-sink cursor, batching, retry
 │ exporter  │──▶ Postgres (COPY + ON CONFLICT DO NOTHING)
 │           │──▶ Kafka / ClickHouse / file  (sink plugins, SPI)
 └───────────┘   ExportCheckpoint(sinkId, position) → cluster
```

### Gateway (implemented in Phase 1) — built on `radius-codec`

- **UdpAgent** owns a NIO `DatagramChannel`: receive, validate (`RadiusPacket.wrap`), look up the NAS by
  source IP, verify the Request Authenticator (and Message-Authenticator if present), extract the hot
  attributes, answer retransmits from the **response cache** (RFC 5080 §2.2.2; key = source address,
  Identifier, Request Authenticator), attach duplicates of in-flight requests instead of resubmitting.
  The same agent sends the Accounting-Response, so replies leave from the socket the NAS sent to.
- **ClusterClientAgent** owns the Aeron Cluster client: offers commands, keeps polling egress even while
  the cluster backpressures or elects a leader, matches `AccountingCommitted` to pending requests.
- Hand-off between them: two Agrona `OneToOneRingBuffer`s carrying SBE bytes (zero-copy). Full ring →
  drop (the NAS retries); never answer without a commit. A retransmit of a request pending for over 1 s
  is resubmitted, which recovers commands lost with a failed leader ([ADR 0011](adr/0011-gateway-pipeline.md)).
- Scale-out: more gateway pods, or `SO_REUSEPORT` with several UdpAgents per pod.
- Everything per packet is allocation-free (`HotPathAllocationIT`).

### Cluster (implemented in Phase 1)

- Three nodes, majority commit = leader + one follower; survives one node down.
- `aeron.archive.file.sync.level=2` and catalog sync level 2: committed means fsynced on a majority.
- **AccountingService** (deterministic, cluster time only):
  - **per-session dedup**: last applied `(status type, session time, counters)` per logical session;
    an event that is not newer is a duplicate and gets the original outcome;
  - Stop tombstones and a short exact-key window for events without a monotonic field;
  - memory scales with concurrent sessions (~80 B each), not with event volume — see ADR 0003/0004;
  - streamed snapshots; hourly automatic snapshot + log purge below
    `min(snapshot position, slowest required sink checkpoint)`.
- Logical event key excludes `Acct-Delay-Time` and the RADIUS Identifier; per-vendor
  `EventKeyStrategy` (Cisco, Juniper, MikroTik, Huawei, Meraki, Ruckus first).

### Exporter and sinks (Phase 3)

- Tails the committed cluster log through an Archive replay — the log already is the durable journal,
  so no backlog is held in cluster memory.
- Sinks are plugins (`AccountingSink` via `ServiceLoader`), several active at once, each with its own
  reader thread, cursor, batching and retry. At-least-once delivery + idempotent sinks (unique `event_id`).
- Postgres sink: plain JDBC, binary `COPY` into a staging table + `INSERT ... ON CONFLICT DO NOTHING`,
  time-partitioned tables, one writer connection.
- Lag policy per sink: `required: true` → `onMaxLag: block` (stop ACKing new accounting),
  otherwise `detach` (release the log, alert). Prometheus lag metrics with early alerts.

## Threading model

| Thread (agent) | Owns | Never does |
|---|---|---|
| UdpAgent | socket, packet codec instances, response cache | block, allocate per packet, talk to Aeron |
| ClusterClientAgent | Aeron cluster client, pending-request map | touch the socket |
| Cluster service | session table, dedup state | I/O, wall clock, randomness |
| Exporter sink threads | one sink each | write to the cluster except checkpoints |

Idle strategies are backoff/sleeping in the small profile (≤1 CPU), busy-spin only in the latency profile.

## Sizing (reference load)

1,000 NAS × 500 sessions = **500k concurrent sessions**, interim interval 1–5 min:

| | 5 min interim | 1 min interim |
|---|---|---|
| steady requests | ~1.7k/s | ~8.3k/s |
| peak (mass reconnect) | ~10k/s | ~16k/s |
| session state | ~40 MB | ~40 MB |
| log growth per node | ~3 GB/h | ~15 GB/h |

Codec cost measured in Phase 0: ~2.2 M packets/s per core for the full receive path
([testing/strategy.md](testing/strategy.md)). Measured locally in Phase 1 (M4 Pro, small profile, fsync on):
ACK latency p50 ~20 ms, p99 ~45 ms; `kill -9` of the leader under load → ~6 s outage, every event
acknowledged after retransmission.

## Memory profiles (ADR 0004)

| Profile | Cluster node | Gateway | Aeron terms | Threading |
|---|---|---|---|---|
| small (default) | 1 GiB (heap ~384 MB) | 256–384 MiB | 1–4 MB | SHARED, backoff idle |
| standard | 2 GiB | 512 MiB | 8 MB | SHARED_NETWORK |
| large | 4 GiB+ | 1 GiB | 16–64 MB | DEDICATED, busy-spin |

## Deployment (planned)

- **Phase 0–1:** local only, no Docker: in-JVM test harness, single-process dev mode, `scripts/run-local.sh`.
- **Phase 2:** one container image with entrypoints `cluster-node | gateway | exporter`, docker-compose.
- **Phase 4:** Helm chart — cluster as a StatefulSet with a headless Service and one PVC (~100 GB) per
  node, `/dev/shm` as `emptyDir: Memory`, anti-affinity, `PodDisruptionBudget maxUnavailable: 1`;
  gateways behind a UDP LoadBalancer with `externalTrafficPolicy: Local` so the NAS source IP is kept.
  systemd units for bare metal.
- Inter-node traffic is always `aeron:udp`; shared memory is only used inside a pod.
- Images built by GitHub Actions on Java 25, published to GHCR.
