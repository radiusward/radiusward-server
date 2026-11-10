# Plan: Phase 5 — authentication and authorization

Status: done (2026-11-10); decisions 1–7 taken; work packages 5.1–5.23 done (ADR 0020–0047). Starts with PAP and CHAP; MS-CHAPv2, EAP (TLS, PEAP, TTLS) and
RadSec follow in the same architecture (roadmap: "external auth adapter → cluster decision, EAP design review,
RadSec").

## Goals and limits

- Answer Access-Requests within a NAS timeout with room to spare: target p99 < 20 ms for PAP/CHAP at 5,000 req/s per
  gateway (a mass reconnect after an outage), with no allocation per packet on the PAP/CHAP path.
- Secure by default: per-NAS secrets, Message-Authenticator required on Access-Request and first in every reply
  (BlastRADIUS, CVE-2024-3596), no secrets or passwords in logs, credentials never stored reversibly unless an
  operator chooses a method that needs it.
- One decision function for every method: authenticate → authorize (pure) → reply; side effects only after Accept.
- Cluster state (sessions) is used where authorization needs it — simultaneous use, quotas — not for every request.
- Not in Phase 5: captive-portal UI, user management UI, CoA/Disconnect (RFC 5176; Phase 6 candidate).

## Design rules

- **Authenticate, then decide, then act.** Authorization is a pure function of the request, the NAS entry, the user
  record and cluster facts; side effects (reservations, counters) happen only after an Accept and are idempotent.
- **EAP is an explicit state machine.** An Access-Accept requires the final state reached through a verified inner
  credential and result; nothing else (a type byte, a flag) can lead there.
- **The tenant comes from the NAS entry** (source address and its secret); request attributes only select within it.
- **Message-Authenticator** is required on Access-Request by default and is the first attribute of every reply.
- **Retransmissions are answered from the response cache** (RFC 5080), and a conversation advances one step at a
  time, so a retransmit never repeats work.
- **Everything is bounded:** worker pools and their queues, store timeouts, conversation tables, reassembly buffers;
  when full, drop (the NAS retransmits).
- **Credentials:** hashed where the method allows it, never logged, never cached outside the store and the
  verification cache; packets are logged redacted.
- **Class** is an HMAC-authenticated token with a key id and rotation.
- **No shared mutable crypto objects and no thread-local request context;** each request carries its own context.
- **TLS** through a supported keying-material exporter (RFC 5705), TLS 1.2 and 1.3, RFC 5216 fragmentation, a DRBG for
  State and challenges.
- **MS-MPPE keys** are always RFC 2548-encrypted; key derivation has known-answer tests.
- **Rejects carry a generic reason** on the wire; the detail goes to metrics and logs.

## Architecture

```text
NAS ──UDP 1812──► gateway: AuthAgent (NIO, own socket)            cluster (only when a policy needs it)
                    validate → NAS entry → Message-Authenticator   ┌──────────────────────────────────┐
                    → response cache → method (PAP/CHAP/…)  ──────►│ AuthReservation (simultaneous use,│
                    → IdentityStore (cache, async I/O pool)        │  quota) through the log           │
                    → Policy (pure) → reply / reservation    ◄─────│ answer after commit               │
                                                                   └──────────────────────────────────┘
```

- **AuthAgent** in the gateway process, beside the accounting `UdpAgent`: same NIO model, NAS registry, response
  cache and Message-Authenticator handling; its own socket (1812) and its own counters. The receive thread never
  blocks: a request that needs I/O goes to a **bounded** worker pool; full → drop.
- **IdentityStore** (plug-in SPI like sinks): looks up a user's credentials and attributes. Built-ins: `file`
  (properties/YAML, tests and small sites) and `sql` (JDBC; a FreeRADIUS-`radcheck`/`radreply`-compatible schema
  option); later `rest` (portal integration, like rlm_rest) and `ldap`. Results cached per gateway with a short TTL and
  explicit invalidation; a store outage → no answer (the NAS retries or falls back), never Accept.
- **Credential formats** per user: PAP verifies salted hashes (`$argon2id$`, `$2y$` bcrypt, `$6$` SHA-512-crypt,
  PBKDF2); CHAP needs the cleartext (RFC 1994) — allowed only where an operator enables CHAP for that store;
  MS-CHAPv2 needs the NT hash (MD4) — stored as `NT-Password`, not cleartext. Slow hashes (argon2/bcrypt) cost
  10–100 ms of CPU: verified on the worker pool, with a per-gateway cache of successful verifications (keyed by
  user + hash of the presented password, short TTL) so a reconnect storm does not cost a hash per request.
- **Policy** (pure function, unit-tested): inputs = NAS entry (tenant), user record, request attributes, optional
  cluster facts; output = Accept + attributes or Reject + internal reason. Rules: account enabled/expiry, NAS/tenant
  binding, time-of-day, Session-Timeout / Idle-Timeout / Acct-Interim-Interval / VLAN (Tunnel-Type 13) / Filter-Id /
  bandwidth via per-vendor attribute **templates** (data, not scripts).
- **Cluster involvement** only for rules that need the replicated session state: *simultaneous use* and later
  *quotas*. The gateway sends an `AuthReservation` command (user, NAS, device, limit) through the log; the state
  machine counts active sessions plus reservations not yet followed by an Accounting-Start (short TTL, closes the
  Accept→Start race) and answers granted/denied; the Accept goes out after the commit (same ACK boundary as
  accounting). Without such a rule nothing touches the cluster, so plain PAP/CHAP latency is local.
- **Class token**: `v1 | key id | HMAC-SHA256(key, tenant | user | auth time | nonce)` + those fields; accounting can
  verify it and the exporter stores the authenticated identity with the session (anonymous outer identities,
  rewritten User-Names).

## EAP (designed now, built after PAP/CHAP)

- **Conversation state machine** per conversation: `IDENTITY → METHOD_START → TLS_HANDSHAKE → TUNNEL → INNER_AUTH →
  RESULT → DONE|FAILED`; every transition checked; the Accept requires `DONE` reached through a verified inner
  credential and Result TLV. One step at a time per conversation; a retransmitted request gets the cached reply.
- **State**: fresh 16-byte DRBG token per round; conversations keyed by State (+ NAS entry), not source port.
  Bounded table (count, bytes), TTL ~60 s, freed on completion; TLS engines and buffers pooled (~50–70 KB each).
- **Where**: node-local in the gateway that started it. A UDP load balancer with source-IP affinity keeps a NAS on
  one gateway; on gateway loss a conversation restarts (the supplicant retries). TLS engine state is not replicated.
- **TLS**: TLS 1.2 and 1.3, server certificate + chain from files with reload on change, client-certificate
  validation for EAP-TLS (trust store, revocation via CRL/OCSP, EKU/SAN policy). Keys via the RFC 5705 exporter —
  the JDK 25 exporter (decision 3). MSK per RFC 5216 / RFC 9427 (TLS 1.3) / PEAP / RFC 5281 labels.
- **Fragmentation** RFC 5216: fragment size from Framed-MTU minus overhead (cap configurable), L bit with the total on
  the first fragment, reassembly of client fragments up to 64 KiB, ACKs, refuse larger totals.
- **Methods**, in order: EAP-TLS, PEAPv0/EAP-MSCHAPv2 (Result TLV success/failure, cryptobinding), EAP-TTLS/PAP and
  /MSCHAPv2 (`ttls challenge` derived from the tunnel); EAP-MD5 only if asked for (no keys, weak). Unknown or refused
  types → NAK-driven offer or EAP-Failure + Access-Reject, never an empty Challenge.
- **Keys**: MS-MPPE-Send/Recv-Key RFC 2548-encrypted with a fresh salt on every Accept that has keys (all EAP
  methods that derive an MSK, and MS-CHAPv2 outside EAP).

## Work packages

| # | Package | Contents | Size |
|---|---|---|---|
| 5.1 ✅ | Codec | Access-Request view, User-Password decrypt (RFC 2865 §5.2, length 16..128, ×16), CHAP verify (RFC 1994), Access-Accept/Reject/Challenge builder with Message-Authenticator first, attribute templates; zero allocation; RFC vectors | M |
| 5.2 ✅ | AuthAgent | non-blocking NIO socket 1812, NAS entries (their secret, `access.message-authenticator` default required), reply cache with in-flight marks, bounded slots and worker pool, counters, `/metrics` | M |
| 5.3 ✅ | IdentityStore SPI + `file` + `sql` | credential formats and verification, caching, timeouts, radcheck-compatible schema option ([ADR 0021](../adr/0021-identity-stores.md)); bcrypt included, argon2 and yescrypt deferred | M |
| 5.4 ✅ | Reply attributes | user and group reply items, vendor filter per NAS entry, reply items checked at load, encoded once, large replies cached ([ADR 0022](../adr/0022-reply-attributes.md)) | S |
| 5.5 ✅ | Simultaneous use via the cluster | `AuthReservation` command, distinct devices per user, reservations until the Accounting-Start, same device always let in, state version 6 (`atLeast(6)`) ([ADR 0023](../adr/0023-simultaneous-use.md)) | M |
| 5.6 ✅ | MS-CHAPv1/v2 (non-EAP), Status-Server | RFC 2433/2759, NT-Password (or cleartext with `mschap` opt-in), MS-CHAP2-Success, RFC 3079 MPPE keys encrypted per RFC 2548, MS-CHAP-Error; Status-Server (RFC 5997) on both ports ([ADR 0024](../adr/0024-ms-chap-and-status-server.md)) | S |
| 5.6b ✅ | Active Directory (Netlogon, pure Java) + LDAP store | a credential-verifier plug-in type next to identity stores; MS-NRPC over TCP: DC discovery (DNS SRV), secure channel with a machine account (NetrServerReqChallenge/Authenticate3, AES session key), Netlogon-signed and sealed RPC as DCs require since CVE-2020-1472, NetrLogonSamLogon network logon for MS-CHAPv1/v2 (and PAP) returning the user session key for MPPE; failover between DCs, timeouts (no answer → no answer to the NAS), machine password rotation; tests against a Samba AD DC container in `-Plinux`. Done: credential-verifier plug-in type, LDAP store and bind verifier, the `netlogon` verifier (endpoint mapper, AES secure channel, sealed RPC, network logons, DNS discovery, failover, metrics), through a real gateway. Open: a check against a Windows domain controller; no machine-password rotation by design ([ADR 0025](../adr/0025-credential-verifiers-and-ldap.md)) | L |
| 5.7 ✅ | EAP framework | conversations keyed by single-use State tokens, bounded node-local table with timeout, method interface with Nak, EAP-Success/Failure, MSK → MS-MPPE keys, EAP-MD5 for the plumbing; `radeapclient` interop ([ADR 0026](../adr/0026-eap-framework.md)). TLS fragmentation moves to 5.8 with the methods that need it | M |
| 5.8 ✅ | EAP-TLS, PEAP, TTLS | TLS engine + exporter, methods above, certificates, `eapol_test` interop: milestone 1 Java 25 baseline ([ADR 0027](../adr/0027-java-25-baseline.md)), milestone 2 EAP-TLS ([ADR 0028](../adr/0028-eap-tls.md)), milestone 3 PEAPv0/EAP-MSCHAPv2 ([ADR 0029](../adr/0029-peap.md)), milestone 4 TTLS with PAP and MS-CHAPv2 ([ADR 0030](../adr/0030-ttls.md)), milestone 4b PEAP inner EAP-GTC and EAP-TLS ([ADR 0031](../adr/0031-peap-inner-methods.md)), milestone 5 PEAP crypto-binding and `eapol_test` interop ([ADR 0032](../adr/0032-peap-crypto-binding.md)), client certificate identity, CRL/OCSP revocation, reload ([ADR 0033](../adr/0033-client-certificates.md)). PEAPv1: not planned (practically unused) | L |
| 5.9 ✅ | RadSec (RFC 6614) | TLS over TCP on `SSLEngine` without Netty, authentication and accounting on one connection, NAS by source address plus optional certificate name, secret `radsec`, the same decision and commit paths through rings, connection limits and timeouts, metrics; interop through radsecproxy with `radclient` and `eapol_test` ([ADR 0034](../adr/0034-radsec.md)). Not covered: DTLS, dynamic discovery (RFC 7585), proxying | M |
| 5.10 ✅ | RadSec additions | a NAS entry identified by its client certificate alone (no fixed address: NAT, dynamic IPs); TLS resumption for RadSec reconnects within `radsec.session.timeout`, stateful sessions because the JDK does not age stateless tickets ([ADR 0034](../adr/0034-radsec.md)) | S |
| 5.11 ✅ | EAP session resumption | TLS 1.2 session IDs and TLS 1.3 PSK for EAP-TLS, PEAP, TTLS within `auth.eap.tls.session.timeout`; PEAP and TTLS fast reconnect for the remembered inner user, who is authorized again; crypto-binding from the tunnel key on fast reconnect; failed sessions invalidated; `eapol_test -r 1` interop ([ADR 0035](../adr/0035-eap-session-resumption.md)) | M |
| 5.12 ✅ | CoA / Disconnect (RFC 5176) | CoA-Request and Disconnect-Request to the NAS (port 3799 or its RadSec connection), ACK/NAK, retries, metrics. Session identification (Acct-Session-Id, User-Name, NAS address/identifier, Framed-IP, Calling-Station-Id) is kept per active session in the replicated state (state version 7). Triggers: the admin API (by user or session), Simultaneous-Use (the oldest session is disconnected instead of the new one rejected), store changes found by a rate-limited sweep of users with active sessions (disabled: Disconnect; changed reply items: CoA). Milestones: 1 ✅ session identity in the state, store off-heap to keep 2M sessions in a small member ([ADR 0036](../adr/0036-coa-and-session-identity.md), [0012](../adr/0012-session-store-dedup.md)), 2 ✅ sender + admin API, 3 ✅ Simultaneous-Use, 4 ✅ store sweep, 5 ✅ interop with an external RADIUS server as CoA receiver | L |
| 5.13 ✅ | Proxying, RadSec client, dynamic discovery | realms (`@realm`, `DOMAIN\`, default) strictly local or proxied; home servers and pools (failover, load-balance per device); Access-Requests proxied by a non-blocking agent (User-Password, CHAP, Message-Authenticator, Proxy-State, MS-MPPE keys and Tunnel-Password re-encrypted), EAP passed through; Status-Server health and failover; RadSec client; proxied accounting committed in the cluster first, then forwarded by a `radius` export sink with retries and lease; NAPTR/SRV discovery (RFC 7585) for TLS home servers. CoA from home servers back to the NAS followed in 5.19. Milestones: 1 ✅ realms and home servers, 2 ✅ UDP proxy, 3 ✅ health and failover ([ADR 0037](../adr/0037-proxying.md)), 4 ✅ RadSec client, 5 ✅ accounting forwarding, 6 ✅ discovery, 7 ✅ interop with radsecproxy and an external RADIUS server ([ADR 0037](../adr/0037-proxying.md)) | L |
| 5.14 ✅ | DTLS (RFC 7360) | RADIUS over DTLS 1.2 on 2083/udp (the JDK has no DTLS 1.3); radsecproxy as the interop client. Milestones: 1 ✅ DTLS associations in the RadSec agent: NAS by address or certificate, secret `radius/dtls`, handshake retransmission, restarted NAS, idle timeout, accounting deduplicated across UDP/RadSec/DTLS, CoA over the association ([ADR 0038](../adr/0038-dtls.md)); 2 ✅ interop with radsecproxy as the DTLS client of `radclient` and `eapol_test`. Not covered: DTLS 1.3 (not in the JDK), the gateway as a DTLS client of home servers | M |
| 5.15 ✅ | PEAP alignment | PEAPv0 only as other servers (PEAPv1 not planned until a user with old Cisco PEAP/GTC clients asks); PEAP and TTLS version bits checked; `auth.eap.peap.client.certificate`; `ExternalEapComparisonIT`: the same `eapol_test` profiles against an installed external RADIUS server and the gateway end the same way, resume alike ([ADR 0039](../adr/0039-peap-alignment.md)) | S |
| 5.16 ✅ | TTLS inner methods | CHAP, MS-CHAPv1 and EAP inside TTLS (EAP-MSCHAPv2, EAP-GTC, EAP-MD5; `auth.eap.ttls.inner`); `eapol_test` and comparison profiles ([ADR 0040](../adr/0040-ttls-inner-methods.md)) | S |
| 5.17 ✅ | TEAP | TEAPv1 (RFC 7170/9930) with inner EAP-MSCHAPv2, EAP-GTC, EAP-MD5, EAP-TLS or Basic-Password-Auth, Crypto-Binding, machine and user chaining; `eapol_test` 2.12 built from source; comparison profiles ([ADR 0041](../adr/0041-teap.md)) | M |
| 5.18 ✅ | EAP-pwd | RFC 5931 with group 19, password preparation none (cleartext) or MS (NT hash), interop and comparison ([ADR 0042](../adr/0042-eap-pwd.md)) | M |
| 5.19 ✅ | CoA relay | CoA and Disconnect-Requests from home servers (`home.<id>.coa`) relayed to the NAS of the user's session; ACK/NAK with Proxy-State back, 503/506 when no session or no answer ([ADR 0043](../adr/0043-coa-relay.md)) | S |
| 5.20 ✅ | Inner-tunnel proxying | `proxy.inner`: the tunnel ends here, the inner user of a proxied realm is checked by its home server (PAP, CHAP, MS-CHAPv2 with MPPE keys for the bindings), its reply attributes ours ([ADR 0044](../adr/0044-inner-tunnel-proxying.md)) | M |
| 5.21 ✅ | RADIUS over TCP | plain TCP (RFC 6613) on 1812/1813 in the RadSec agent, NAS by address with its own secret, ports keep their kind ([ADR 0045](../adr/0045-radius-over-tcp.md)) | S |
| 5.22 ✅ | Dynamic clients | NAS entries looked up on demand in SQL (`nas` table) for unknown addresses of configured networks, off the packet path, with lifetimes and a negative cache ([ADR 0046](../adr/0046-dynamic-clients.md)) | M |
| 5.23 ✅ | IPv6 NAS | IPv6 entries and ranges (longest prefix first), dual-stack listening, CoA by NAS-IPv6-Address ([ADR 0047](../adr/0047-ipv6-nas.md)) | S |

## Tests

- Known-answer vectors: RFC 2865 PAP, RFC 1994 CHAP, RFC 2759/3079 MS-CHAPv2 and MPPE, RFC 2548 encryption with an
  injectable salt, TLS 1.2/1.3 exporter MSK vectors.
- Property tests: decoders never throw on random input; a wrong credential never yields Accept.
- Allocation test for the PAP/CHAP path (like `HotPathAllocationIT`).
- Interop: FreeRADIUS `radclient` (PAP/CHAP/MS-CHAP, `-Pinterop`) and `eapol_test` from wpa_supplicant in a container
  (`EapolTestIT`, a Docker test in `./mvnw verify`: EAP-TLS, PEAP, TTLS, TLS 1.2 and 1.3, fragmentation, crypto-binding,
  wrong credentials). Retransmissions mid-handshake are covered by the response cache and conversation tests, as
  `eapol_test` cannot drop packets.
- Cluster IT: simultaneous use across two gateways (reservations), gateway restart, store outage.
- Load: reconnect storm of 50k users through two gateways; p99 and drops.

## Decisions

1. **First identity store** (decided 2026-11-09): `sql` with a FreeRADIUS `radcheck`/`radreply`-compatible option,
   plus `file` for tests and small sites; `rest` and `ldap` later.
2. **CHAP and cleartext** (decided 2026-11-09): per-store opt-in. Stores hold salted hashes by default (PAP only);
   CHAP works only where the operator enables cleartext for that store; MS-CHAP uses NT hashes.
3. **TLS stack for EAP** (decided 2026-11-09): the JDK's own JSSE with the keying-material exporter added in Java 25
   (`ExtendedSSLSession.exportKeyingMaterialKey/Data`, JDK-8341346; RFC 5705 for TLS ≤ 1.2, RFC 8446 for 1.3) — no
   Bouncy Castle dependency, no reflection into JDK internals, TLS fixes with the JDK's security updates. MSKs:
   `client EAP encryption` / `ttls keying material` without context (TLS 1.2), `EXPORTER_EAP_TLS_Key_Material` with
   the EAP type as context (TLS 1.3, RFC 9190 / RFC 9427), `ttls challenge` for TTLS inner challenges. The project
   baseline moves from Java 21 to **Java 25** (the current LTS; the image and release builds already run it) no
   later than work package 5.8 — done in 5.8 milestone 1 ([ADR 0027](../adr/0027-java-25-baseline.md)).
4. **Identity stores** (decided 2026-11-09, [ADR 0021](../adr/0021-identity-stores.md)): stores run in the gateway
   workers; one ordered list `auth.stores` with an optional `nas.<name>.auth.stores`; our own bounded JDBC
   connection pool. Password formats in our own code, no runtime library: cleartext, SHA-crypt, bcrypt, salted
   SHA, PBKDF2 (Bouncy Castle only as a test reference). argon2 and yescrypt are deferred until there is demand.
   When needed, yescrypt (`$y$`, `/etc/shadow` on current Linux) follows the same model: own verification code on
   JDK SHA-256/HMAC (scrypt core, `pwxform`, libxcrypt's default flags only, other modes rejected), a memory ceiling,
   and — with no Java reference implementation — committed fixtures generated with libxcrypt in a container plus
   the reference known-answer vectors. argon2 would use Bouncy Castle as a test reference, like bcrypt.
5. **Scope of 5.4** (decided 2026-11-09, [ADR 0022](../adr/0022-reply-attributes.md)): only reply attributes and mixed
   NAS vendors — reply items per user and group, a vendor filter per NAS entry. The check items of 5.3 stay as they
   are and are not extended. Deferred until operators ask: vendor-neutral templates, `Login-Time`, binding users to
   NAS entries, the signed Class token, reject reasons in metrics.
6. **Simultaneous use** (decided 2026-11-09, [ADR 0023](../adr/0023-simultaneous-use.md)): the same device never
   counts twice; sessions with a lost Stop count until their NAS entry's idle timeout; cluster unreachable → no answer
   for limited users only; before state version 6 is active the limit is ignored; users matched by User-Name (ASCII
   case folded) across all NAS entries.
7. **MS-CHAP** (decided 2026-11-09, [ADR 0024](../adr/0024-ms-chap-and-status-server.md)): v1 and v2; `NT-Password`
   always, cleartext only with `auth.store.<name>.mschap`; MPPE keys always on success; generic `E=691`. Status-Server
   on both ports. Active Directory through a pure-Java Netlogon client (5.6b), not through Samba's `ntlm_auth`.
