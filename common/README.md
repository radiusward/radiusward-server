# common

Shared runtime pieces, no business logic:

| Class | Role |
|---|---|
| `config.Config`, `ConfigArgs`, `ConfigException` | properties files + `RADIUSWARD_*` environment overrides + `${env:...}` secrets, typed accessors; durations, sizes and lists through `units` ([ADR 0010](../docs/adr/0010-configuration.md)) |
| `Profile` | small / standard / large: Aeron term lengths, threading, idle strategy, logging ring, capacities ([ADR 0004](../docs/adr/0004-memory-budget.md)) |
| `management.ManagementServer`, `Health`, `JsonWriter` | `/health`, `/ready`, `/state` on the JDK HTTP server ([ADR 0013](../docs/adr/0013-operational-endpoints-logging.md)) |
| `PrometheusWriter`, `JvmMetrics` | `/metrics` in the Prometheus text format without a client library; the JVM metrics every process exposes |
| `logging.NonBlockingQueueFullPolicy`, `Logging` | Log4j2 async loggers that never block the caller; per-profile settings |
| `net.DnsCache` | short-lived name lookups, so members and RADIUS servers follow pods to new addresses ([ADR 0062](../docs/adr/0062-members-and-gateways-on-kubernetes.md)) |

Resources: `log4j2.xml` (console; rolling file with `-Dradiusward.log.dir`) and `log4j2.component.properties`
(async selector, non-blocking policy, garbage-free settings incl. `SystemMillisClock`).
