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
| Fault injection (Linux) | `testing/linux-tests` | `./mvnw -Plinux verify` / `scripts/linux-tests.sh`, nightly CI | shipped image + compose config in containers: power loss of all members (LazyFS, with a no-fsync negative control), partition, full disk, overload at the memory limits, failover timing, compose smoke ([ADR 0016](../adr/0016-fault-injection-tests.md)) |
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

All current fixtures are **synthetic** (built from vendor documentation). Real captures are better; see
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
