# Test strategy

## Pyramid

| Level | Where | Runs | What it proves |
|---|---|---|---|
| Unit | `src/test/java/**/*Test.java` | `./mvnw verify` (Surefire, with JaCoCo) | parser, codec, generator behaviour |
| Property-based fuzzing | `CodecFuzzTest`, `Aaa4jDifferentialTest` (jqwik) | `./mvnw verify` | decoder and Access-Request credential handling never throw or read out of bounds; agreement with aaa4j on random attribute sets and passwords |
| Differential | `Aaa4jDifferentialTest` | `./mvnw verify` | our codec and aaa4j-radius accept each other's packets and authenticators; User-Password encrypted by either decrypts in the other; aaa4j verifies our Access-Accept/Reject/Challenge |
| Standard vectors | `RadiusAuthenticatorTest` | `./mvnw verify` | RFC 2865 §7.1 response authenticator and User-Password, RFC 2104/2202 HMAC-MD5; `AccessRequestsTest`: CHAP against an independent JDK reference |
| Vendor fixtures | `VendorFixtureTest` | `./mvnw verify` | 33 packets (BNG: Cisco, Juniper, Juniper ERX, MikroTik, Huawei; Wi-Fi: Aruba, Meraki, MikroTik hotspot, Open-Mesh, Ruckus, Ubiquiti UniFi × Start/Interim/Stop) encode byte-exactly, verify, extract correctly; aaa4j decodes them too |
| Allocation | `HotPathAllocationIT` (Failsafe, no JaCoCo) | `./mvnw verify` | 1M accounting packets through the receive path allocate < 4 KB in total; so do 1M PAP + CHAP Access-Requests with replies |
| Interop | `FreeRadiusInteropIT`, `FreeRadiusClientInteropIT` | `./mvnw -Pinterop verify` (FreeRADIUS 3.2 from `brew install freeradius-server`; found on the PATH or in Homebrew's directories, skipped if missing) | a real FreeRADIUS accepts our accounting requests and we verify its responses; FreeRADIUS's `radclient` gets correct answers from our gateway for PAP, CHAP, MS-CHAPv1 (MPPE keys, `E=691`) and Status-Server |
| Loopback UDP | `RadClientTest` | `./mvnw verify` | radclient against a codec-based responder: retries, timeouts, Message-Authenticator |
| Protocol | `ProtocolRoundTripTest` | `./mvnw verify` | every SBE message round-trips; a v1 decoder reads v2 |
| State machine | `AccountingStateMachineTest`, `DuplicatesPropertyTest`, `SnapshotAndReplayTest`, `StateMachineAllocationIT` | `./mvnw verify` | dedup rules, duplicates never change results, a Start delayed behind its session's Interim or Stop never changes the session's result, any arrival order of all events ends in the same sessions as in-order delivery, snapshots and replay are deterministic, no allocation |
| Gateway component | `UdpAgentTest`, `GatewayAllocationIT` | `./mvnw verify` | real loopback UDP with the cluster simulated through the rings; no allocation per packet, also with device identities; every vendor fixture keeps its session with the attribute it sends in every packet |
| Access-Requests | `AuthAgentTest`, `ReplyCacheTest`, `GatewayAuthIT`, `GatewayAllocationIT` | `./mvnw verify` | signed Accept/Reject over loopback UDP with Message-Authenticator first; required Message-Authenticator (and with EAP); retransmissions dropped while decided, then answered from the cache; full slots drop; handler errors survive; 8 concurrent clients × 250 requests through 4 workers each get their own reply; no allocation per request |
| Identity stores | `PasswordCheckTest`, `ShaCryptTest`, `BCryptTest`, `StoreAccessHandlerTest`, `AuthStoresTest`, `FileStoreTest`, `SqlStoreTest`, `GatewayAuthIT` | `./mvnw verify` (`SqlStoreTest` needs Docker) | credential formats against JDK references, the SHA-crypt and bcrypt vectors, and Bouncy Castle (test scope) for bcrypt over random inputs; the bcrypt cost ceiling; PAP/CHAP decisions with check items, groups, reply merge and vendor attributes; store order, outage → no answer, look-up and slow-hash caching; users-file parsing and reload; SQL schema, injection safety, bounded pool, unreachable database; the real gateway answering PAP and CHAP from a users file; reply vendor filter per NAS entry and its counter; reply items checked at load; concurrent workers with their own caches always decide correctly; large replies in the reply cache |
| Simultaneous use | `SimultaneousUseTest`, `SessionStoreTest`, `UserKeysTest`, `ClusterReservationsTest`, `StoreAccessHandlerTest`, `UdpAgentTest`, `SimultaneousUseIT` | `./mvnw verify` | version gate (ignored before 6, same digest as older code); distinct devices online and reserved; same device let in; expiry and sweep; unknown devices; capacity; Accounting-On and idle timeout free places; snapshot round trip decides alike; keys equal across MAC notations and name case; worker mailbox and timeout; three members and two gateways: the limit holds across gateways and a Stop frees the place |
| MS-CHAP, Status-Server | `MsChapTest`, `StoreAccessHandlerTest`, `PasswordCheckTest`, `AuthAgentTest`, `UdpAgentTest`, `GatewayAuthIT` | `./mvnw verify` | MD4 (RFC 1320), MS-CHAPv2 and authenticator response (RFC 2759 §9.2), MPPE master/send key (RFC 3079 §3.5.3); RFC 2548 key encryption reversed as a NAS does; v1 keys; errors E=691; cleartext only with the opt-in; DOMAIN\\user; NT-Password for PAP; Status-Server answered only with a valid Message-Authenticator, on accounting only while connected, never cached; MS-CHAPv2 through a real gateway |
| LDAP, verifiers, Netlogon | `LdapStoreTest`, `StoreAccessHandlerTest`, `AuthStoresTest`, `NetlogonCryptoTest`, `SecureChannelIT`, `NetlogonVerifierIT`, `GatewayNetlogonIT`, `DomainControllersTest` | `./mvnw verify` (Docker: a Samba AD domain controller from `testing/samba-ad`) | users, groups, nested groups, required groups, policies, attribute mapping, disabled accounts, filter injection; PAP by binding as the user, no empty-password binds; LDAPS with an own CA, plain LDAP refused; failover; verifiers chosen by store or Auth-Type, MS-CHAP from a verifier's session key (RFC 2759 vector), unavailable → no answer; Netlogon: endpoint mapper, AES secure channel, wrong machine password refused, sealed network logons with the expected session key; the verifier for MS-CHAPv1/v2 and PAP, three user-name forms, rejections, 8 threads on 2 channels, unreachable DC and wrong machine password → unavailable; MS-CHAPv2 through a real gateway with the LDAP store (success value and MPPE keys right, group policy applied, a non-member rejected); DNS SRV ordering and refresh; failover past a silent domain controller; a frozen one (container paused): no answers, then a fresh channel. These fault scenarios run as Docker tests in the module, not in `-Plinux`: they need no radiusward image |
| EAP framework | `EapPacketTest`, `EapConversationsTest`, `StoreAccessHandlerTest`, `FreeRadiusClientInteropIT` | `./mvnw verify`, `-Pinterop` | EAP over several `EAP-Message` attributes, malformed packets; State single-use, per NAS, expiry, bounded table with sweep; EAP-MD5 conversation to EAP-Success with reply items; EAP-Failure on wrong password, unknown user, used or expired State, Nak to an unoffered method; an answer to another request not answered; EAP-MD5 needs the chap opt-in; `radeapclient` gets Accept and Reject from a real gateway |
| EAP-TLS | `EapTlsTest`, `GatewayAuthIT` | `./mvnw verify` | test certificates from Bouncy Castle (test scope); a JDK TLS client as the peer: TLS 1.3 and 1.2 to EAP-Success, MS-MPPE keys equal to the MSK the client exports itself, fragments of 90–100 bytes both ways, untrusted or missing client certificate → EAP-Failure, certificate-only users, `require.user`, message limit; over UDP through a real gateway with Message-Authenticator and challenges over 1 KiB, a store entry rejecting a certified device |
| PEAP | `EapTlsTest`, `PeapPeer` | `./mvnw verify` | PEAPv0/EAP-MSCHAPv2 with TLS 1.3 and 1.2, anonymous outer identity, the inner user's NT hash or cleartext opt-in, its reply items, the client checking the server's authenticator response, MPPE keys equal to the client's; wrong password (MS-CHAPv2 Failure, then EAP-Failure), unknown and rejected inner users; an inner verifier, and its outage: no answer, then the retransmission continues the conversation |
| TTLS | `EapTlsTest`, `TtlsPeer` | `./mvnw verify` | TTLS/PAP on TLS 1.2 and 1.3 with cleartext and SHA-crypt passwords, reply items and keys; wrong password; TTLS/MS-CHAPv2 with the implicit challenge, server proof checked, a relayed challenge refused; PAP through a verifier and its outage (no answer, the retransmission repeats only the check) |
| PEAP inner methods | `EapTlsTest`, `PeapPeer` | `./mvnw verify` | EAP-GTC chosen by Nak, checked against a SHA-crypt hash and through a PAP-only verifier; a Nak to an unoffered method; EAP-TLS inside PEAP with a certificate-only user, an untrusted inner certificate rejected |
| Tunnels against Active Directory | `TunnelNetlogonIT` (in `verifiers/netlogon`, with the gateway test-jar) | `./mvnw verify` (Docker: Samba AD) | PEAP/MS-CHAPv2 on TLS 1.3 and 1.2, TTLS/MS-CHAPv2 and TTLS/PAP, PEAP/GTC: users from the LDAP store, credentials checked by the Netlogon verifier, the client verifying the server's proof built from the session key the domain controller returned; wrong password, account disabled in the domain |
| `eapol_test` interop | `EapolTestIT` | `./mvnw verify` (Docker: `testing/eapol-test`) | wpa_supplicant 2.10 against the real gateway over UDP: EAP-TLS, PEAP (MS-CHAPv2, GTC, inner EAP-TLS), TTLS (PAP, MS-CHAPv2), each on TLS 1.2 and 1.3 with 400-byte fragments both ways; PEAP with crypto-binding required and off; `eapol_test` compares the MS-MPPE keys with its own MSK; wrong passwords, a disabled user, a certificate of another CA, an identity that is not the certificate's; each run's log in `gateway/target/eapol-test` |
| Crypto-binding, client certificates | `PeapCryptoBindingTest`, `CertificateIdentityTest`, `EapTlsTest` | `./mvnw verify` | PRF+ blocks, the Crypto-Binding TLV both ways (another inner key, another nonce, a reflected request fail), the MS-CHAPv2 ISK; binding required without an answer, a broken one, off; certificate names (CN, e-mail, DNS, UPN, `host/`), identity `match`, `certificate` (UPN names the user), `any`; CRL revoked, issuer without CRL (hard, soft fail); OCSP from a test responder (good, revoked, unreachable hard and soft); reload: a certificate without its key kept out, then the renewed pair served, metrics; mismatched key at start |
| RadSec | `RadsecIT`, `RadsecConfigTest`, `RadsecAccountingIT` (test-harness), `RadsecproxyIT` | `./mvnw verify` (Docker for `RadsecproxyIT`: `testing/radsec-client`) | Access-Requests and Status-Server over TLS 1.3 and 1.2 signed with the RadSec secret; 200 requests in flight on one connection; no client certificate or one of another CA: handshake fails; certificate not naming the NAS, NAS entry without RadSec: closed; malformed length closes, unknown codes ignored; handshake timeout; accounting over RadSec committed by 3 members and the same Start over UDP a duplicate; radsecproxy 1.11 as the client of `radclient` (PAP accept/reject) and `eapol_test` (PEAP with crypto-binding, TTLS) with MPPE keys intact; radsecproxy's log in `gateway/target/radsec-client` |
| Cluster (in-JVM) | `ThreeNodeClusterIT`, `LocalClusterIT` | `./mvnw verify` | real Aeron Cluster members and gateways in one JVM: commit, failover, snapshot, restart, load; sessions without a Start, late Starts, Interims in reverse order and an Interim older than the tombstone window acknowledged over UDP without moving the session back |
| End-to-end | `testing/e2e-tests` | `./mvnw -Pe2e verify` | separate JVMs from `radiusward.jar`, real `kill -9`: the 8 scenarios in [failure-matrix.md](failure-matrix.md) |
| Fault injection (Linux) | `testing/linux-tests` | `./mvnw -Plinux verify` / `scripts/linux-tests.sh`, nightly CI | shipped image + compose config in containers: power loss of all members (LazyFS, with a no-fsync negative control), partition, full disk, overload at the memory limits, failover timing, compose smoke ([ADR 0016](../adr/0016-fault-injection-tests.md)) |
| Export | `ExporterIT`, `PostgresExportIT`, `LogPurgeIT`, `LogReplicaSpikeIT` (in-JVM cluster), `PostgresSinkTest` (Testcontainers; skipped without Docker, required in CI) | `./mvnw verify` | lease handover without gap or duplicate, exactly-once rows, admin tools, purge |
| Logging | `NonBlockingLoggingIT` | `./mvnw verify` | async, garbage-free, never blocks on a full ring |
| Benchmarks | `testing/benchmarks`, `-Pbench` | manual | throughput baselines |

## Coverage

`./mvnw verify` measures unit tests only and enforces the module floors of `radius-codec` (90 % lines,
generated code excluded) and `radius-dictionary` (80 %). Most of the cluster, exporter and sink code is only
reached by the integration tests, so a second, honest measurement covers both:

```bash
./mvnw -Pcoverage verify -Dradiusward.require.docker=true    # report: testing/coverage/target/site/jacoco-aggregate/
```

- The `coverage` profile instruments Failsafe (`jacoco-it.exec`) as well as Surefire and builds one aggregate
  report over all modules in `testing/coverage`. CI runs it as the `coverage` job and uploads the report.
- The allocation ITs (`*AllocationIT`) are excluded from it: the JaCoCo agent allocates and would fail them.
  They still run in the normal build.
- Generated code (SBE codecs in `io.radiusward.protocol`, hot-attribute accessors) is excluded; the generators
  have their own tests.
- `-Pe2e` processes are not instrumented, so `distribution` (the `main` entry points) shows 0 % here and has no
  floor; `test-harness` is test support and has none either.
- `testing/coverage/floors.properties` holds a line floor per module and for the total, a few points below the
  measured value; `check-floors.sh` fails the build below any of them. Raise a floor when a module gains
  tests; never lower one to let a change pass.

Measured 2026-11-08 (lines / branches): total 89.7 %; radius-codec 98.7 / 94.0, common 97.5 / 91.2,
cluster-service 95.5 / 84.6, radius-codegen 95.2 / 82.1, sink-file 94.4 / 76.4, sink-postgres 93.6 / 80.0,
admin-cli 93.1 / 80.6, exporter 91.1 / 81.0, gateway 90.1 / 81.0, export-api 87.4 / 73.7, radclient 86.0 / 72.0,
cluster-node 82.5 / 65.6, radius-dictionary 81.7 / 67.7. The first measurement (total 87 %) found untested
configuration validation (`GatewayConfig`, `ClusterNodeConfig`), admin command paths and exporter decisions,
now tested (`GatewayConfigTest`, `ClusterNodeConfigTest`, `ExportDecisionsTest`, `ExportVerifierTest`), and two
bugs: a PostgreSQL partition cached by a rolled-back transaction sent later good rows to quarantine, and the
admin client did not reconnect after the cluster closed its idle session.

## Vendor fixtures

`radius-codec/src/test/resources/fixtures/<vendor>/<event>.fixture`:

```text
# Cisco IOS-XE ISG, PPPoE subscriber session start.
# SYNTHETIC: built from the Cisco ISG RADIUS attribute documentation, not a capture.
identifier: 17
attributes:
  Acct-Status-Type: Start          # dictionary names; VALUE names or numbers for integers
  Framed-IP-Address: 100.64.0.10
  Cisco.AVPair: connect-progress=Call Up
  Ruckus.BSSID: 0x2c5d93000010     # 0x... for raw bytes
packet: 0411...                     # signed with secret "testing123"; written by -Dfixtures.update=true
expect:
  statusType: 1                     # AccountingFields field name → expected value
  ciscoAvPair: a|b                  # repeated fields joined with |
  outputOctets64: 13958643712       # <name>Octets64 combines the counter with its gigawords
```

The test rebuilds the packet from `attributes:` and requires it to equal `packet:` byte for byte, so an
unintended encoder change fails. Use `-Dfixtures.update=true` only after an intended change, and review
the diff.

### Replacing synthetic fixtures with captures

All current fixtures are **synthetic** (built from vendor documentation). They encode what is known of each device:
Aruba writes MACs without separators and sends no Class in accounting; Ubiquiti UniFi puts the AP MAC in
NAS-Identifier and links roaming with Acct-Multi-Session-Id; Open-Mesh sends an **empty** NAS-Identifier (length 2 —
decoded fine, treated as no identity); a MikroTik hotspot's Called-Station-Id is the hotspot server name, not a
MAC. `UdpAgentTest` pins, per vendor, the attribute sent in every packet (for `nas.<name>.identity`) and fails when a
fixture vendor has none. Open questions only captures can settle: whether MikroTik hotspot counts octets from the
router's side (reported by deployments; radiusward stores the values as sent), and whether Meraki sends
Called-Station-Id in Interim/Stop. Real captures are better; see
[vendor-captures.md](vendor-captures.md) for capturing, `radclient decode --fixture --anonymise` and the
review checklist.

## Latency in containers (Phase 2)

Compose stack, small profile (members 1 CPU / 1 GiB, gateways 384 MiB), Colima VM on an Apple M4 Pro
(8 CPU, 12 GiB). `radclient load` from the tools container through both gateways, 30 s per run; latency is
request sent → verified Accounting-Response. Idle CPU: gateway container 5 s after start, no traffic.

| `archive.file.sync.level` | `gateway.idle.strategy` | 200 req/s p50 / p99 | 2,000 req/s p50 / p99 | gateway idle CPU |
|---|---|---|---|---|
| 2 | `sleep-1ms` | 6.5 / 45 ms | 2.7 / 58 ms | 5.2 % |
| 2 | `backoff-100us` | 5.3 / 37 ms | **1.6 / 47 ms** | 6.0 % |
| 1 | `sleep-1ms` | 6.3 / 40 ms | 2.2 / 52 ms | 6.1 % |
| 1 | `backoff-100us` | 5.1 / 43 ms | 1.3 / 51 ms | 6.1 % |
| 0 | `sleep-1ms` | 5.8 / 48 ms | 2.2 / 60 ms | 6.0 % |
| 0 | `backoff-100us` | 4.9 / 54 ms | 1.0 / 73 ms | 6.3 % |

- **Default chosen:** `backoff-100us` for small and standard (was a 1 ms sleep): lower p50 for well under one
  percentage point of idle CPU. `busy-spin` stays limited to the large profile.
- **fsync** costs almost nothing here because the VM's disk is backed by the macOS page cache. On real disks
  the fsync of each batch is what bounds commit latency; measure on the target hardware (SSD with power-loss
  protection recommended). Keep level 2 regardless: lower levels lose acknowledged events on power loss
  (`PowerLossIT`).
- Throughput: ~32k requests/s served with all members at one CPU each (`OverloadIT`); a single `radclient
  load` process tops out around 8k/s, so use several (`--first-session`).
- p99 is dominated by scheduling jitter of one-CPU containers on a shared VM, not by radiusward's code path.

## Export throughput (Phase 3)

`ExportThroughputIT`: compose-like containers (members 1 CPU / 1 GiB), PostgreSQL 17 in a container on the same
Colima VM; a backlog of ~75k events (15k sessions, 20 s at 3k/s) built with PostgreSQL down, then drained.

| Variant | Drain rate | Rows | Bytes per event row | Bytes per session row |
|---|---|---|---|---|
| `sessions` (default) | ~27k events/s | 15,000 sessions | — | ~750 B |
| `sessions+events`, residual JSON | ~18.8k events/s | + 74,884 events | ~300 B | ~740 B |
| `sessions+events`, raw attribute bytes | ~18.6k events/s | + 74,884 events | ~380 B | ~740 B |
| `sessions+events`, typed columns only | ~18.5k events/s | + 74,883 events | ~300 B | ~740 B |

- Every variant drains 6–9× faster than this intake, and far faster than the reference load (8.3k/s worst case).
- The load generator only sends attributes that have typed columns, so the residual JSON is empty here and costs
  nothing; its real cost needs vendor captures (P2.8). Raw bytes add ~80 B per event.
- Session rows include index and dead-tuple overhead from updates (every session was updated ~5 times).
- Not yet measured: GIN and expression indexes, a separate payload table, binary `COPY` — left for Phase 3b,
  they matter only for attribute-heavy history.

## Benchmark baseline (Phase 0)

Apple M4 Pro, JDK 21, JMH 1 fork, 3 × 1 s measurement; packet: ~200 byte Cisco interim update.

| Benchmark | Throughput |
|---|---|
| `validate` | ~63 ops/µs |
| `extract` | ~13 ops/µs |
| `encodeResponse` | ~9.6 ops/µs |
| `verifyAuthenticator` | ~3.4 ops/µs |
| `fullReceivePath` (validate + verify + extract + respond) | **~2.2 ops/µs ≈ 2.2 M packets/s per core** |

MD5 dominates. The reference peak load is ~16k requests/s, so one core has >100× headroom. Re-run after
codec changes and compare with `-prof gc` to confirm zero allocation (`gc.alloc.rate.norm ≈ 0`).
