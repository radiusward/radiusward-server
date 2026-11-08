# common

Shared runtime pieces, no business logic:

| Class | Role |
|---|---|
| `config.Config`, `ConfigArgs` | properties files + `RADIUSWARD_*` environment overrides + `${env:...}` secrets, typed accessors ([ADR 0010](../docs/adr/0010-configuration.md)) |
| `Profile` | small / standard / large: Aeron term lengths, threading, idle strategy, logging ring, capacities |
| `management.ManagementServer`, `Health`, `JsonWriter` | `/health`, `/ready`, `/state` on the JDK HTTP server |
| `logging.NonBlockingQueueFullPolicy`, `Logging` | Log4j2 async loggers that never block the caller ([ADR 0013](../docs/adr/0013-operational-endpoints-logging.md)) |

Resources: `log4j2.xml` (console; rolling file with `-Dradiusward.log.dir`) and `log4j2.component.properties`
(async selector, non-blocking policy, garbage-free settings incl. `SystemMillisClock`).
