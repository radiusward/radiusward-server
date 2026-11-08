# Configuration

Properties files, one or more per process (`--config a.properties --config b.properties`, later files win).
Every key can be overridden by an environment variable — `cluster.node.id` → `RADIUSWARD_CLUSTER_NODE_ID` —
and values may reference the environment: `${env:NAS_SECRET}`, `${env:X:-default}` ([ADR 0010](adr/0010-configuration.md)).
Durations: `500ms`, `10s`, `5m`, `2h`. Sizes: `512`, `64k`, `4m`, `1g`. Examples: [config/local](../config/local).

## Common

| Key | Default | Meaning |
|---|---|---|
| `profile` | `small` | `small` \| `standard` \| `large` — Aeron term lengths, threading, idle strategy, logging ring, capacities ([ADR 0004](adr/0004-memory-budget.md)) |
| `management.http.enabled` | `true` | management HTTP server on/off |
| `management.http.host` | `127.0.0.1` | bind address (`0.0.0.0` inside a pod) |
| `management.http.port` | node: `9090+id`, gateway: `9189+gateway.id` | `/health`, `/ready`, `/state` |
| `cluster.members` | `localhost,localhost,localhost` | member hosts in member-id order (nodes and gateways) |
| `cluster.base.port` | `9000` | member *i* uses `base + 100·i + {ingress 0, consensus 1, log 2, catchup 3, archive 4, replication 5}` |

In the container image the entrypoint sets defaults (as environment variables, so files still win):
`cluster.data.dir=/var/lib/radiusward`, `cluster.aeron.dir=/dev/shm/radiusward-node`,
`gateway.aeron.dir=/dev/shm/radiusward-gateway`, `dictionary.dir=/etc/radiusward/dictionary.d`,
`management.http.host=0.0.0.0`; heap from `RADIUSWARD_PROFILE` ([docker.md](operations/docker.md)).

System properties: `radiusward.log.dir` (also write a rolling file), `radiusward.log.level` (default `INFO`).

## Cluster node

| Key | Default | Meaning |
|---|---|---|
| `cluster.node.id` | — (required) | index into `cluster.members` |
| `cluster.data.dir` | `.local/data` | archive and cluster directories go to `<dir>/node-<id>/` |
| `cluster.aeron.dir` | temp dir per node | Aeron media driver directory (`/dev/shm` on Linux) |
| `cluster.leader.heartbeat.timeout` | `1500ms` | leader failure detection; with the election timeout a crashed leader is replaced in ~2.2 s, below a 3 s NAS timeout ([ADR 0011](adr/0011-gateway-pipeline.md)) |
| `cluster.election.timeout` | `500ms` | how long a candidate waits for votes |
| `cluster.session.timeout` | `10s` | client session timeout |
| `archive.file.sync.level` | `2` | `0` page cache, `1` fsync data, `2` fsync data + metadata; the archive catalog and the cluster's recording log and node state use the same level. Below `2` a power loss can lose acknowledged events or stop members from starting (`PowerLossIT`) |
| `cluster.disk.min.free` | `1g` | below this free space in the data directory the member reports not ready (`/ready`, with the reason) and logs a warning; a full disk stops the member. `0` disables |
| `snapshot.interval` | `1h` | automatic snapshot on the leader; `0` disables |
| `service.max.sessions` | profile (small: 2,000,000) | session capacity; new sessions beyond it are rejected |
| `service.tombstone` | `1h` | how long a stopped session is kept to recognise retransmitted Stops |
| `service.idle.timeout` | `2h` | remove sessions with no event for this long (lost Stop) |
| `service.exact.key.window` | `15m` | remember exact keys of events without progress values |
| `service.sweep.interval` | `60s` | housekeeping timer |

## Gateway

| Key | Default | Meaning |
|---|---|---|
| `gateway.id` | `1` | distinct per gateway |
| `gateway.listen.host` / `gateway.listen.port` | `0.0.0.0` / `1813` | RADIUS accounting socket |
| `gateway.socket.receive.buffer` | `4m` | `SO_RCVBUF` |
| `gateway.egress.host` | `localhost` | address the cluster sends replies to (the pod IP in Kubernetes) |
| `gateway.aeron.dir` | temp dir per process | embedded media driver directory |
| `gateway.threading` | `shared` (`dedicated` for large) | both agents on one thread, or one each |
| `gateway.idle.strategy` | profile: `backoff-100us` (small, standard), `busy-spin` (large) | how the gateway threads wait when idle: `sleep-1ms` \| `backoff-1ms` \| `backoff-100us` \| `busy-spin`; trades CPU for latency (measurements in [testing/strategy.md](testing/strategy.md#latency-in-containers-phase-2)) |
| `gateway.pending.capacity` | profile (small: 16,384) | requests in flight; beyond it packets are dropped |
| `gateway.pending.timeout` | `5s` | forget a request with no commit (the next retransmit is submitted again) |
| `gateway.retransmit.resubmit.after` | `1s` | a retransmit of a request pending longer than this is resubmitted ([ADR 0011](adr/0011-gateway-pipeline.md)) |
| `gateway.response.cache.ttl` | `30s` | how long committed requests are answered from the cache |
| `dictionary.dir` | `/etc/radiusward/dictionary.d` | operator dictionaries, loaded after the bundled set if the directory exists |
| `debug.enabled` | `false` | allows `debug.*` keys; never in production |
| `debug.response.delay` | `0` | hold Accounting-Responses back (tests only; requires `debug.enabled=true`) |

## NAS clients (gateway)

| Key | Default | Meaning |
|---|---|---|
| `nas.<name>.address` | — | IPv4 address or CIDR range of the NAS |
| `nas.<name>.secret` | — | shared secret; use `${env:...}` |
| `nas.<name>.vendor` | `default` | vendor profile |
| `nas.<name>.message-authenticator` | `optional` | `required` \| `optional` \| `off` |
| `nas.<name>.id` | FNV-1a hash of the name | identity used in event keys — must be identical on every gateway |
