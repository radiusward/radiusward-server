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
| [0027](0027-java-25-baseline.md) | Java 25 baseline, for the TLS keying-material exporter | Accepted |
| [0028](0028-eap-tls.md) | EAP-TLS: JDK TLS engine, RFC 5216 framing, keys from the exporter, certificate-only users | Accepted |
| [0029](0029-peap.md) | PEAPv0/EAP-MSCHAPv2: shared TLS base, the inner user is authorized, outages keep the conversation | Accepted |
| [0030](0030-ttls.md) | EAP-TTLS with inner PAP and MS-CHAPv2, implicit challenge | Accepted |
| [0031](0031-peap-inner-methods.md) | PEAP inner methods: EAP-GTC (like PAP) and EAP-TLS, chosen by Nak | Accepted |
| [0032](0032-peap-crypto-binding.md) | PEAP crypto-binding (optional by default), `eapol_test` interop for every TLS method | Accepted |
| [0033](0033-client-certificates.md) | Client certificates: identity must match (or names the user), CRL/OCSP revocation, reload on change | Accepted |
| [0034](0034-radsec.md) | RadSec (RFC 6614): TLS over TCP on `SSLEngine` (no Netty), NAS by address and certificate, same decision paths through rings | Accepted |
| [0035](0035-eap-session-resumption.md) | EAP session resumption per gateway, PEAP/TTLS fast reconnect with the inner user authorized again | Accepted |
| [0036](0036-coa-and-session-identity.md) | CoA/Disconnect; sessions' identifying attributes in the replicated state (version 7), off-heap, 2M sessions still in 1 GiB | Accepted |
| [0037](0037-proxying.md) | Proxying realms to home servers: strictly local or proxied, non-blocking on the auth thread, everything re-encrypted, Status-Server health | Accepted |
| [0038](0038-dtls.md) | RADIUS over DTLS 1.2 (RFC 7360) in the RadSec agent: associations per NAS address, retransmission, one packet per record | Accepted |
| [0039](0039-peap-alignment.md) | PEAPv0 only (PEAPv1 not planned), version bits checked, PEAP client certificates, EAP compared with an external server | Accepted |
| [0040](0040-ttls-inner-methods.md) | TTLS with CHAP, MS-CHAPv1 and EAP inside (MS-CHAPv2, GTC, MD5); challenges from the tunnel, MS-CHAPv1 exported at its own length | Accepted |
| [0041](0041-teap.md) | TEAP (RFC 7170/9930): inner EAP or Basic-Password-Auth, Crypto-Binding as wpa_supplicant/hostapd, machine and user chaining | Accepted |
| [0042](0042-eap-pwd.md) | EAP-pwd (RFC 5931), group 19, cleartext or NT-hash preparation, own P-256 arithmetic | Accepted |
| [0043](0043-coa-relay.md) | CoA and Disconnect from home servers relayed to the NAS of the user's session, answered with their Proxy-State | Accepted |
| [0044](0044-inner-tunnel-proxying.md) | Tunnels end here, the inner user of a proxied realm is checked by its home server (PAP, CHAP, MS-CHAPv2 with its keys) | Accepted |

Format: context, decision, consequences. A superseded ADR stays and links to its replacement.
