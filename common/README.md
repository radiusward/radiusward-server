# radiusward-common

`radiusward-common` holds the runtime pieces every radiusward process shares, with no business logic: configuration
from properties files and the environment, resource profiles, the management HTTP server with health, readiness,
state and metrics, and Log4j2 logging that never blocks the caller. Cluster members, RADIUS servers and the backup
process start through it.

**Stability:** Internal: published as a dependency of `radiusward-embedded` and the radiusward server; it may change in any release.

## Use it

You normally do not depend on it directly: the radiusward server, the cluster modules and `radiusward-embedded`
bring it. Plug-ins get their own settings from the context they are created with (`radiusward-auth-api`,
`radiusward-export-api`), not from `Config`.

## What's inside

| Type | Role |
|---|---|
| `config.Config`, `ConfigArgs`, `ConfigException` | properties files (later files win) + `RADIUSWARD_*` environment overrides + `${env:NAME}` / `${env:NAME:-default}` secrets; typed accessors that fail naming the key; durations, sizes and lists through [radiusward-units](../units/README.md) ([ADR 0010](../docs/adr/0010-configuration.md)) |
| `Profile` | `SMALL` (the default, a member in 1 GiB), `STANDARD`, `LARGE`: Aeron term lengths, media driver threading, idle strategy, logging ring, session capacity, in-flight requests ([ADR 0004](../docs/adr/0004-memory-budget.md)) |
| `management.ManagementServer`, `Health`, `JsonWriter` | `/health`, `/ready`, `/state` and `/metrics` on the JDK HTTP server; more paths through `handle(path, handler)` ([ADR 0013](../docs/adr/0013-operational-endpoints-logging.md)) |
| `management.PrometheusWriter`, `JvmMetrics` | `/metrics` in the Prometheus text format without a client library; the JVM metrics every process exposes |
| `logging.NonBlockingQueueFullPolicy`, `Logging` | Log4j2 async loggers that drop an event instead of blocking when the ring is full, whatever its level (`dropped()` counts them, shown in `/state`); per-profile settings |
| `net.DnsCache` | `shortLived()`: a 1 s name cache and no negative cache, so members and RADIUS servers follow pods to new addresses ([ADR 0062](../docs/adr/0062-members-and-gateways-on-kubernetes.md)) |

**Resources.** `log4j2.xml` (console; a rolling file with `-Dradiusward.log.dir`) and `log4j2.component.properties`
(async logger context selector, the non-blocking queue-full policy, garbage-free settings including
`SystemMillisClock`). Never log per packet on the hot path; use parameterized, garbage-free calls only.

`Config` is immutable and thread-safe, read at startup and never on the hot path.

## Configuration

`Config` reads any key; the ones every process shares are `profile`, `management.http.*`, `cluster.members` and
`cluster.base.port`:

```properties
profile=standard
management.http.host=0.0.0.0
management.http.port=9090
cluster.members=node-0,node-1,node-2
```

```bash
RADIUSWARD_PROFILE=large                        # overrides profile
```

All keys: [docs/configuration.md](../docs/configuration.md#common).

## Requirements

Java 25 and `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` (Agrona). Runtime dependencies: Agrona,
Log4j2 (`log4j-api`, `log4j-core`) and the LMAX Disruptor, all Apache-2.0; `radiusward-units`.

## Learn more

- [Configuration](../docs/configuration.md)
- [ADR 0010: configuration](../docs/adr/0010-configuration.md), [ADR 0004: memory budget](../docs/adr/0004-memory-budget.md),
  [ADR 0013: operational endpoints and logging](../docs/adr/0013-operational-endpoints-logging.md)
- [ADR 0062: members and RADIUS servers on Kubernetes](../docs/adr/0062-members-and-gateways-on-kubernetes.md)

## License

Apache-2.0.
