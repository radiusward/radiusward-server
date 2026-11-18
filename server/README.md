# RADIUS server

The NAS-facing process: accounting over UDP ([ADR 0006](../docs/adr/0006-nio-udp-transport.md),
[ADR 0011](../docs/adr/0011-gateway-pipeline.md)), authentication, EAP, RadSec, DTLS and TCP, proxying and CoA; the
replicated state is in the cluster.

```bash
java -jar distribution/target/radiusward.jar server --config config/local/server-a.properties --config config/local/nas-clients.properties
```

| Class | Role |
|---|---|
| **Wiring** | |
| `RadiusServer`, `ServerAssembly`, `ServerConfig`, `ServerMain`, `ServerStats` | the RADIUS server and how it is put together: dictionary, embedded media driver, rings, agents and threads, management; `server.*`; the `radiusward server` entry point (SIGHUP reload, drain on SIGTERM); counters |
| **Accounting** | |
| `UdpAgent`, `UdpReceiver` | owns the accounting socket: validate, NAS lookup, authenticators, response cache, extract, event keys, submit; builds and sends the response after commit; the socket read in batches, shared with RadSec's requests |
| `ClusterClientAgent` | owns the Aeron Cluster client: `tryClaim` into the cluster, polls egress while back-pressured, reconnects |
| `NasRegistry`, `NasClient`, `NasConfig`, `DeviceIdentity` | configured NAS by source address (IPv4 exact, allocation-free; CIDR; IPv6), secret, Message-Authenticator policy; the device behind an entry ([ADR 0019](../docs/adr/0019-nas-device-identity.md)) |
| `EventKeys`, `Murmur3`, `UserKeys` | session key and exact key (pinned layout, one for every vendor); user and device keys shared with simultaneous use |
| `ResponseCache`, `PendingTable` | RFC 5080 duplicate detection, state only (PENDING with correlation id / COMMITTED); preallocated in-flight requests |
| `DynamicClients` | NAS entries looked up on demand in SQL for unknown addresses, off the packet path, copy-on-write table ([ADR 0046](../docs/adr/0046-dynamic-clients.md)) |
| **Authentication** | |
| `AuthAgent` | Access-Requests ([ADR 0020](../docs/adr/0020-authentication-path.md)): its own non-blocking socket; validate, NAS lookup, Message-Authenticator (required by default), reply cache, hand-off to the workers, send the replies; delayed rejects ([ADR 0057](../docs/adr/0057-reject-delay.md)) |
| `AccessWorker`, `AccessSlots`, `AccessHandler`, `AccessContext` | bounded hand-off to worker threads that decide a request (`AccessHandler`) and build the signed reply |
| `ReplyCache`, `AuthConfig`, `AuthStats`, `AuthMetrics`, `StoreLookups`, `EnumCounters` | RFC 5080 reply cache with in-flight marks; `server.auth.*`; counters, store look-ups and EAP outcomes for `/metrics` |
| `StoreAccessHandler`, `AuthRequest`, `AccessPolicies` | the store handler: one request's state on a worker, and the settings it takes once per request so a reload never mixes them |
| `AuthStores`, `UserDirectory`, `CheckItems`, `ValueComparison` | identity stores from `auth.*` ([ADR 0021](../docs/adr/0021-identity-stores.md)); the user found and authorized: stores in order, check items, groups |
| `PasswordChecks`, `PasswordCheck`, `ShaCrypt`, `BCrypt`, `Yescrypt`, `Md5Crypt`, `TotpFactor`, `Totp` | the credential against the stores or a verifier ([ADR 0025](../docs/adr/0025-credential-verifiers-and-ldap.md)); stored formats: cleartext, SHA-crypt, bcrypt, yescrypt, MD5-crypt, salted SHA, PBKDF2, legacy digests ([ADR 0048](../docs/adr/0048-password-formats.md)); TOTP as a second factor ([ADR 0053](../docs/adr/0053-totp.md)) |
| `MsChap`, `MsChapAuthenticator` | MS-CHAPv1/v2 verification, authenticator response, MPPE keys and their RFC 2548 encryption ([ADR 0024](../docs/adr/0024-ms-chap-and-status-server.md)) |
| `Admission`, `Restrictions`, `SessionLimits`, `ClusterReservations` | after the credential: Expiration, Expire-After, Login-Time, usage counters, Simultaneous-Use through the cluster with a mailbox per worker ([ADR 0023](../docs/adr/0023-simultaneous-use.md), [0049](../docs/adr/0049-time-and-usage-limits.md)) |
| `ReplyEncoder`, `AddressAssignment`, `IpPools`, `LoginTime`, `UsageCounters` | reply items merged and filtered by the NAS entry's vendors ([ADR 0022](../docs/adr/0022-reply-attributes.md)); IPv4 and IPv6 pools in PostgreSQL ([ADR 0050](../docs/adr/0050-ip-pools.md), [0059](../docs/adr/0059-ipv6-pools.md)); Login-Time windows; usage counters over the exported sessions |
| `Rules`, `RulesFile` | the rule layer on Access-Accepts, parsed into typed conditions and actions ([ADR 0051](../docs/adr/0051-rules.md)) |
| `Cui`, `AuthLog`, `Tracer`, `ReloadApi`, `HttpJson`, `OnceLogger` | Chargeable-User-Identity ([ADR 0056](../docs/adr/0056-chargeable-user-identity.md)); the authentication log ([ADR 0058](../docs/adr/0058-authentication-log.md)); per-request traces with secrets hidden ([ADR 0052](../docs/adr/0052-request-traces.md)); reload on SIGHUP or `POST /reload` ([ADR 0054](../docs/adr/0054-config-reload.md)); what the HTTP APIs share; warnings logged once |
| **EAP** | |
| `EapAuthenticator`, `EapPacket`, `EapConversations`, `EapMethod`, `EapMd5`, `EapConfig` | EAP in RADIUS: packets over `EAP-Message`, conversations by single-use State, methods ([ADR 0026](../docs/adr/0026-eap-framework.md)) |
| `TlsTunnel`, `SslEngines`, `EapTls`, `EapTlsConfig`, `TlsCredentials`, `CertificateIdentity` | the JDK TLS engine in RFC 5216 framing with exporter keys; EAP-TLS ([ADR 0028](../docs/adr/0028-eap-tls.md)); the server's certificate, key, client CAs and CRL/OCSP revocation, reloaded when the files change; the identity checked against the certificate ([ADR 0033](../docs/adr/0033-client-certificates.md)) |
| `Peap`, `PeapCryptoBinding`, `Ttls`, `Teap`, `TeapKeys`, `InnerEap`, `InnerCredentials` | PEAPv0 with inner MSCHAPv2, GTC or TLS and crypto-binding ([ADR 0029](../docs/adr/0029-peap.md), [0032](../docs/adr/0032-peap-crypto-binding.md)); TTLS with inner PAP, CHAP, MS-CHAP and EAP ([ADR 0030](../docs/adr/0030-ttls.md), [0040](../docs/adr/0040-ttls-inner-methods.md)); TEAP ([ADR 0041](../docs/adr/0041-teap.md)); inner credentials checked like outer ones, waiting while a store is down |
| `EapPwd`, `P256` | EAP-pwd with group 19 ([ADR 0042](../docs/adr/0042-eap-pwd.md)) |
| `EapSim`, `EapAka`, `Milenage`, `SimKeys`, `SimMessage`, `SimIdentities`, `SimSubscriber`, `SimVectors`, `SimConfig` | EAP-SIM, EAP-AKA and EAP-AKA′ with MILENAGE, sequence numbers from the cluster, pseudonyms and fast re-authentication ([ADR 0061](../docs/adr/0061-eap-sim-aka.md)) |
| **RadSec, DTLS, TCP** | |
| `RadsecAgent`, `StreamConnection`, `DtlsServer`, `RadsecPeers`, `RadsecLink`, `RadsecConfig` | RadSec: TLS over TCP with `SSLEngine`, NAS by address and certificate, packets to the auth and accounting agents and replies back through rings by connection and generation ([ADR 0034](../docs/adr/0034-radsec.md)); RADIUS over DTLS 1.2 on the same agent ([ADR 0038](../docs/adr/0038-dtls.md)); RADIUS over plain TCP ([ADR 0045](../docs/adr/0045-radius-over-tcp.md)) |
| **Proxying** | |
| `Proxy`, `ProxyCodec`, `ProxyConfig`, `SaltedValues`, `HomeServers`, `HomeState` | proxying realms to home servers on the auth thread: the rewritten request and answer with re-encryption and Proxy-State, home server pools, health and failover ([ADR 0037](../docs/adr/0037-proxying.md)) |
| `HomeConnection`, `TlsClient`, `HomeTcpClient`, `HomeDtlsClient`, `ProxyRewrite`, `InnerProxy` | home servers over TLS, TCP and DTLS beside UDP, per-realm pre-/post-proxy rewriting, inner credentials to a home server ([ADR 0044](../docs/adr/0044-inner-tunnel-proxying.md), [0055](../docs/adr/0055-proxy-transports-and-rewriting.md)) |
| `RealmDiscovery`, `DiscoveredRealms` | home servers of realms found in DNS (NAPTR, SRV), off the proxy's thread (RFC 7585) |
| **CoA and Disconnect** | |
| `DynamicAuthorization`, `CoaService`, `CoaApi`, `CoaConfig`, `ClusterQueries`, `DisconnectOldest`, `StoreSweep`, `CoaRelay` | CoA and Disconnect-Requests (RFC 5176): sessions found in the replicated state, requests over UDP, RadSec or DTLS, ACK/NAK and retries, the token-protected HTTP API, Simultaneous-Use disconnecting the oldest session, the store sweep ([ADR 0036](../docs/adr/0036-coa-and-session-identity.md)); relayed from home servers ([ADR 0043](../docs/adr/0043-coa-relay.md)) |

Never blocks and never allocates per packet (`ServerAllocationIT`, 100k accounting packets and 100k
Access-Requests). A retransmit of a request
pending for over 1 s is resubmitted, so commands lost with a failed leader are recovered.
