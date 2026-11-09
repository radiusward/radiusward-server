# gateway

The RADIUS UDP front end ([ADR 0006](../docs/adr/0006-nio-udp-transport.md), [ADR 0011](../docs/adr/0011-gateway-pipeline.md)).

```bash
java -jar distribution/target/radiusward.jar gateway --config config/local/gateway-a.properties --config config/local/nas-clients.properties
```

| Class | Role |
|---|---|
| `UdpAgent` | owns the NIO socket: validate, NAS lookup, authenticators, response cache, extract, event keys, submit; builds and sends the response after commit |
| `ClusterClientAgent` | owns the Aeron Cluster client: `tryClaim` into the cluster, polls egress while back-pressured, reconnects |
| `NasRegistry`, `NasClient` | configured NAS by source address (IPv4 exact, allocation-free; CIDR), secret, Message-Authenticator policy |
| `EventKeys`, `Murmur3` | session key and exact key (pinned layout) |
| `ResponseCache` | RFC 5080 duplicate detection, state only (PENDING with correlation id / COMMITTED) |
| `PendingTable` | preallocated in-flight requests |
| `AuthAgent` | Access-Requests (Phase 5, [ADR 0020](../docs/adr/0020-authentication-path.md)): its own non-blocking NIO socket; validate, NAS lookup, Message-Authenticator (required by default), reply cache, hand-off to the workers, send the replies |
| `AccessWorker`, `AccessSlots`, `AccessHandler`, `AccessContext` | bounded hand-off to worker threads that decide a request (`AccessHandler`) and build the signed reply |
| `ReplyCache`, `AuthConfig`, `AuthStats` | RFC 5080 reply cache with in-flight marks; `gateway.auth.*`; counters |
| `AuthStores`, `StoreAccessHandler` | identity stores from `auth.*` ([ADR 0021](../docs/adr/0021-identity-stores.md)); PAP/CHAP decision: stores in order, check items, groups, reply items filtered by the NAS entry's vendors ([ADR 0022](../docs/adr/0022-reply-attributes.md)); per-worker Agrona caches |
| `SessionLimits`, `ClusterReservations`, `UserKeys` | simultaneous use: reservations through the cluster with a mailbox per worker; user and device keys shared with the accounting path ([ADR 0023](../docs/adr/0023-simultaneous-use.md)) |
| `TlsTunnel`, `EapTls`, `Peap`, `EapTlsConfig` | the JDK TLS engine in RFC 5216 framing with exporter keys; EAP-TLS ([ADR 0028](../docs/adr/0028-eap-tls.md)); PEAPv0 with EAP-MSCHAPv2, inner user authorized ([ADR 0029](../docs/adr/0029-peap.md)) |
| `EapPacket`, `EapConversations`, `EapMethod`, `EapMd5`, `EapConfig` | EAP: packets over `EAP-Message`, conversations by single-use State, methods ([ADR 0026](../docs/adr/0026-eap-framework.md)) |
| `MsChap`, `Md4` | MS-CHAPv1/v2 verification, authenticator response, MPPE keys and their RFC 2548 encryption ([ADR 0024](../docs/adr/0024-ms-chap-and-status-server.md)) |
| `PasswordCheck`, `ShaCrypt`, `BCrypt` | stored credential formats: cleartext, `$5$`/`$6$` SHA-crypt, `$2a$`/`$2b$`/`$2y$` bcrypt, salted SHA, PBKDF2 |
| `Gateway`, `GatewayConfig`, `GatewayMain` | wiring, embedded media driver, threading, management |

Never blocks and never allocates per packet (`GatewayAllocationIT`, 100k accounting packets and 100k
Access-Requests). A retransmit of a request
pending for over 1 s is resubmitted, so commands lost with a failed leader are recovered.
