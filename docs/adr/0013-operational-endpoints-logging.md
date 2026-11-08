# ADR 0013: Operational endpoints and logging

Status: Accepted (2026-11-08)

## Management endpoints
The JDK's built-in `com.sun.net.httpserver.HttpServer` (no dependency), one management port per process:

| Endpoint | Cluster node | Gateway |
|---|---|---|
| `/health` | process and agents running | process and agents running |
| `/ready` | service started, leader known | UDP bound and connected to the cluster |
| `/state` | role, leader, term, log position, applied/duplicates/stale/rejected, sessions, digest, snapshots, dropped logs | packet counters, pending, cache size, connection, dropped logs |
| `/metrics` | Phase 3, Prometheus text | Phase 3 |

Hot-path threads only write counters with release stores; one HTTP worker thread reads them and builds
JSON by hand. No authentication in Phase 1, no secrets in `/state`, no write endpoints (snapshots go through
`radiusward cluster-tool`). Bound to 127.0.0.1 by default.

## Logging
**Log4j2 async loggers backed by the LMAX Disruptor**, and logging never blocks the caller:
- `AsyncLoggerContextSelector` for all loggers;
- `NonBlockingQueueFullPolicy`: when the ring is full, discard whatever the level and count it (Log4j's
  default blocks; its `Discard` policy still blocks for WARN/ERROR) — the count is in `/state`;
- ring size per profile: small 8,192, standard 65,536, large 262,144 slots;
- garbage-free: thread-locals, direct encoders and **`SystemMillisClock`** (the default clock allocates an
  `Instant` per event — found with JFR, ~140 → ~0.5 bytes per call);
- Log4j2 API directly, parameterized messages, `Unbox.box` for primitives, no per-packet logging.

Proven by `NonBlockingLoggingIT`: all loggers async, 100k log calls allocate < 64 KB, 20k ERRORs with a stuck
appender return in < 2 s and are dropped and counted.
