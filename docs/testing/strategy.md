# Test strategy

## Pyramid

| Level | Where | Runs | What it proves |
|---|---|---|---|
| Unit | `src/test/java/**/*Test.java` | `./mvnw verify` (Surefire, with JaCoCo) | parser, codec, generator behaviour |
| Property-based fuzzing | `CodecFuzzTest`, `Aaa4jDifferentialTest` (jqwik) | `./mvnw verify` | decoder never throws or reads out of bounds; agreement with aaa4j on random attribute sets |
| Differential | `Aaa4jDifferentialTest` | `./mvnw verify` | our codec and aaa4j-radius accept each other's packets and authenticators |
| Standard vectors | `RadiusAuthenticatorTest` | `./mvnw verify` | RFC 2865 §7.1 response authenticator, RFC 2104/2202 HMAC-MD5 |
| Vendor fixtures | `VendorFixtureTest` | `./mvnw verify` | 21 packets (Cisco, Juniper, Juniper ERX, MikroTik, Huawei, Meraki, Ruckus × Start/Interim/Stop) encode byte-exactly, verify, extract correctly |
| Allocation | `HotPathAllocationIT` (Failsafe, no JaCoCo) | `./mvnw verify` | 1M accounting packets through the receive path allocate < 4 KB in total |
| Interop | `FreeRadiusInteropIT` | `./mvnw -Pinterop verify` | a real FreeRADIUS accepts our requests and we verify its responses |
| Loopback UDP | `RadClientTest` | `./mvnw verify` | radclient against a codec-based responder: retries, timeouts, Message-Authenticator |
| Protocol | `ProtocolRoundTripTest` | `./mvnw verify` | every SBE message round-trips; a v1 decoder reads v2 |
| State machine | `AccountingStateMachineTest`, `DuplicatesPropertyTest`, `SnapshotAndReplayTest`, `StateMachineAllocationIT` | `./mvnw verify` | dedup rules, duplicates never change results, snapshots and replay are deterministic, no allocation |
| Gateway component | `UdpAgentTest`, `GatewayAllocationIT` | `./mvnw verify` | real loopback UDP with the cluster simulated through the rings; no allocation per packet |
| Cluster (in-JVM) | `ThreeNodeClusterIT`, `LocalClusterIT` | `./mvnw verify` | real Aeron Cluster members and gateways in one JVM: commit, failover, snapshot, restart, load |
| End-to-end | `testing/e2e-tests` | `./mvnw -Pe2e verify` | separate JVMs from `radiusward.jar`, real `kill -9`: the 8 scenarios in [failure-matrix.md](failure-matrix.md) |
| Logging | `NonBlockingLoggingIT` | `./mvnw verify` | async, garbage-free, never blocks on a full ring |
| Benchmarks | `testing/benchmarks`, `-Pbench` | manual | throughput baselines |

Coverage floors (line): `radius-codec` 90 % excluding generated code, `radius-dictionary` 80 %.

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

All current fixtures are **synthetic** (built from vendor documentation). Before Phase 2 they should be
replaced or complemented by real captures:

1. Capture on a lab NAS: `tcpdump -i any -w acct.pcap udp port 1813`.
2. Extract the RADIUS payload of one Accounting-Request (Wireshark → *Export Packet Bytes*, or
   `tshark -r acct.pcap -T fields -e radius` ).
3. **Anonymise**: replace user names, MAC addresses, IPs and session ids with documentation values
   (RFC 5737 / RFC 3849 addresses), keeping lengths and formats.
4. Write the attributes into a `.fixture` (`radclient decode <hex>` prints them), mark it
   `# CAPTURED (anonymised) from <device, software version>`, and run with `-Dfixtures.update=true`.

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
