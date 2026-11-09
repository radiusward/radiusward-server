# Architecture decision records

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-aeron-cluster.md) | Aeron Cluster for replication and consensus | Accepted |
| [0002](0002-ack-boundary.md) | Accounting-Response only after majority commit with fsync | Accepted |
| [0003](0003-event-key-and-dedup.md) | Logical event key and per-session deduplication | Accepted |
| [0004](0004-memory-budget.md) | 1 GiB default memory profile | Accepted |
| [0005](0005-log-determinism-versioning.md) | Deterministic replay across versions | Accepted |
| [0006](0006-nio-udp-transport.md) | Plain NIO `DatagramChannel`, no Netty | Accepted |
| [0007](0007-sink-spi-lag-policy.md) | Pluggable sinks, log-tailing exporter, lag policy | Accepted |
| [0008](0008-dictionaries-licensing-codegen.md) | Bundled CC BY 4.0 FreeRADIUS dictionaries + code generation | Accepted |
| [0009](0009-local-first-development.md) | Local-first development, no Docker in Phase 0–1 | Accepted |
| [0010](0010-configuration.md) | Properties files with environment overrides | Accepted |
| [0011](0011-gateway-pipeline.md) | Gateway pipeline: ring buffers, stateless response cache, resubmission | Accepted |
| [0012](0012-session-store-dedup.md) | SessionStore layout and dedup rules | Accepted |
| [0013](0013-operational-endpoints-logging.md) | Management endpoints; non-blocking Log4j2 async logging | Accepted |
| [0014](0014-log-purge.md) | Log purge (spike result, Phase 3) | Accepted |
| [0015](0015-container-image.md) | Container image and runtime layout | Accepted |
| [0016](0016-fault-injection-tests.md) | Fault injection and durability tests in Linux containers | Accepted |
| [0017](0017-exporter.md) | Exporter inside the member: lease, commit-position bound, state-machine reducer | Accepted |
| [0018](0018-storage-model.md) | Storage model: session-first, opt-in history, stable identities, portable primitives | Accepted |
| [0019](0019-nas-device-identity.md) | Devices behind one NAS entry (NAT): device identity in keys and Accounting-On scope | Accepted |
| [0020](0020-authentication-path.md) | The Access-Request path on the gateway: non-blocking socket agent, bounded workers, reply cache | Accepted |
| [0021](0021-identity-stores.md) | Identity stores: plug-in SPI in the gateway, ordered stores, outage means no answer, credential formats | Accepted |
| [0022](0022-reply-attributes.md) | Reply attributes as data, vendor filter per NAS entry, large replies in the reply cache | Accepted |
| [0023](0023-simultaneous-use.md) | Simultaneous use through the cluster: distinct devices per user, reservations committed before the Accept, state version 6 | Accepted |
| [0024](0024-ms-chap-and-status-server.md) | MS-CHAPv1/v2 from NT hashes, MPPE keys, generic errors; Status-Server on both ports | Accepted |
| [0025](0025-credential-verifiers-and-ldap.md) | Credential verifiers, the LDAP store, pure-Java Netlogon for Active Directory | Accepted |
| [0026](0026-eap-framework.md) | EAP conversations: single-use State tokens, bounded node-local table, method interface, EAP-MD5 | Accepted |

Format: context, decision, consequences. A superseded ADR stays and links to its replacement.
