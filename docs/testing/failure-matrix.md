# Failure matrix

Every failure case, the behaviour radiusward must show, and the test that proves it.
Status: ✅ covered · 🔜 planned (phase).

## Packet level (Phase 0)

| Case | Expected behaviour | Test | Status |
|---|---|---|---|
| datagram shorter than 20 bytes | discard silently | `RadiusPacketTest.tooShort` | ✅ |
| Length field < 20 or > 4096 | discard | `RadiusPacketTest.lengthFieldOutOfRange` | ✅ |
| Length field larger than datagram | discard | `RadiusPacketTest.lengthFieldLargerThanDatagramIsTruncated` | ✅ |
| trailing bytes beyond Length | ignore them, accept packet | `RadiusPacketTest.trailingBytesBeyondLengthAreIgnored` | ✅ |
| attribute length < 2 or past end | discard | `RadiusPacketTest.attributeLengthBelowTwo`, `attributeRunningPastEnd` | ✅ |
| Message-Authenticator length ≠ 18 | discard | `RadiusPacketTest.messageAuthenticatorMustBe18Bytes` | ✅ |
| malformed VSA content | packet accepted, VSA opaque | `AttributeCursorTest.malformedVsaContentIsOpaque` | ✅ |
| wrong secret / tampered packet | authenticator fails → discard | `RadiusAuthenticatorTest.tamperedAccountingRequestFails` | ✅ |
| invalid Message-Authenticator | fails verification | `RadiusAuthenticatorTest.accountingRequestMessageAuthenticator` | ✅ |
| arbitrary garbage | never throws, never reads out of bounds | `CodecFuzzTest` | ✅ |
| hot attribute with wrong value length | counted malformed, reported absent | `AccountingAttributeExtractorTest.malformedAndDuplicateValuesAreCounted` | ✅ |
| more repeats than the limit | extra occurrences counted as dropped | `AccountingAttributeExtractorTest.repeatLimitAndReuse` | ✅ |
| Proxy-State in request | echoed in order in the response | `AccountingResponsesTest` | ✅ |

## Dictionary level (Phase 0)

| Case | Expected behaviour | Test | Status |
|---|---|---|---|
| unknown keyword/type/flag in bundled set | build fails | `DictionaryLoaderTest.Errors` | ✅ |
| same in operator file | skipped with file:line warning | `DictionaryLoaderTest.unknownKeywordLenientWarns` | ✅ |
| `$INCLUDE` cycle or missing file | fails with location | `DictionaryLoaderTest.Includes` | ✅ |
| operator file redefines a type | strict fails, lenient overrides + warns | `DictionaryLoaderTest.Overrides` | ✅ |
| `dictionary.d` missing | warning, continue | `DictionaryLoaderTest.missingDirectoryIsAWarning` | ✅ |
| bundled file without CC BY header | update script fails | `scripts/update-dictionaries.sh` | ✅ |

## Cluster and gateway (Phase 1–2)

`linux` tests run in containers (`-Plinux`, [ADR 0016](../adr/0016-fault-injection-tests.md)).

| Case | Expected behaviour | Test | Status |
|---|---|---|---|
| no majority (2 of 3 members down) | no ACK; after recovery the retransmit is acknowledged, applied once | e2e `AckAfterCommitIT` | ✅ |
| leader killed (-9) under load | every acknowledged event in the state; per-session state = last acked event; replicas equal | e2e `LeaderFailoverIT`, `LocalClusterIT.leaderLossDoesNotLoseAcknowledgedEvents` | ✅ |
| commands lost with the failed leader | retransmit after > 1 s is resubmitted by the gateway; late commits ignored | `UdpAgentTest.retransmitOfALongPendingRequestIsResubmitted`, e2e `LeaderFailoverIT` | ✅ |
| gateway killed after commit, before response | retry via other gateway answered as duplicate, applied once | e2e `GatewayFailoverIT` | ✅ |
| identical retransmit, same gateway | answered from the response cache, no cluster round trip | e2e `RetransmitIT`, `UdpAgentTest` | ✅ |
| retransmit with new Identifier / Acct-Delay-Time / other gateway | same event keys, cluster duplicate, state unchanged | e2e `RetransmitIT`, `UdpAgentTest.eventKeysIgnoreIdentifierAndDelayForAllFixtures` | ✅ |
| follower killed (-9) and restarted at once | waits for the stale mark file, catches up, same digest | e2e `NodeRestartIT` | ✅ |
| snapshot + restart of every member | dedup state restored, old events are duplicates | e2e `SnapshotRestoreIT`, `SnapshotAndReplayTest` | ✅ |
| Accounting-On/Off | all active sessions of the NAS stopped | e2e `AccountingOnOffIT`, `AccountingStateMachineTest` | ✅ |
| Accounting-On/Off from one device behind NAT | only that device's sessions stopped; without its identity none | e2e `DevicesBehindNatIT`, `LocalClusterIT`, `AccountingStateMachineTest` | ✅ |
| Devices behind NAT reuse Acct-Session-Ids | separate sessions per device (`identity`) | `LocalClusterIT` (50 APs, 10 ids), `UdpAgentTest`, `EventKeysTest` | ✅ |
| session capacity reached | new sessions rejected (no ACK), Stops still applied | `AccountingStateMachineTest.capacity` | ✅ |
| lost Stop | session removed after the idle timeout (per NAS entry or default); exported stop time = last event | `AccountingStateMachineTest`, `SnapshotAndReplayTest`, `BatchBuilderTest` | ✅ |
| duplicates in any position | never change the result | `DuplicatesPropertyTest` (jqwik) | ✅ |
| pending table or ring full | packet dropped, counted; NAS retransmits | `UdpAgentTest.fullPendingTableDrops` | ✅ |
| logging ring full | log events dropped and counted, caller never blocks | `NonBlockingLoggingIT` | ✅ |
| leader cut off from both followers (iptables) | minority never acknowledges; majority elects a new leader, gateways follow; after healing the old leader rejoins as follower, digests equal, nothing acknowledged lost | linux `PartitionIT` | ✅ |
| leader `kill -9` at ~2k requests/s in containers | writable again in ~2.2 s, 0 retransmissions | linux `FailoverTimingIT`, e2e `LeaderFailoverIT` | ✅ |
| data directory nearly full | member reports not ready with the reason, warning logged | linux `DiskFullIT`, `ThreeNodeClusterIT` | ✅ |
| data directory full | member stops (SIGBUS on a mapped file), majority continues, replaced member catches up, nothing acknowledged lost | linux `DiskFullIT` | ✅ |
| power loss of all three members at once | with fsync level 2 every acknowledged event survives; level 0 loses them (negative control) | linux `PowerLossIT` (LazyFS) | ✅ |
| sustained overload (1.5× capacity, 2M sessions) | memory bounded under the container limits, no OOM kill, gateways drop and the NAS retries, consistent afterwards | linux `OverloadIT` | ✅ |
| shipped compose file | starts healthy, both gateways acknowledge | linux `ComposeSmokeIT` | ✅ |

## Export (Phase 3)

| Case | Expected behaviour | Test | Status |
|---|---|---|---|
| PostgreSQL down under load (30 min nightly) | ACKs continue, lag grows, backlog drains afterwards, every acknowledged session in the database | linux `PostgresOutageIT` | ✅ |
| required sink over `maxLag` | new accounting not acknowledged (`EXPORT_LAG`), ACKs resume after catch-up, nothing acknowledged missing | linux `ExportLagBlockIT`, `ThreeNodeClusterIT`, `LogApplierTest` | ✅ |
| optional sink over `maxLag` | detached, ACKs never stop, re-attaches after catch-up, the lease stays put | linux `DetachIT`, `ExportStateTest` | ✅ |
| exporting member stopped under load | lease moves with a new epoch, no gap, no duplicate | `ExporterIT`, `PostgresExportIT` | ✅ |
| stale exporter writes after a handover | refused by the epoch fence, batch rolled back | `PostgresSinkTest.anOlderEpochIsFenced`, `FileSinkTest` | ✅ |
| connection lost mid-batch | nothing partial visible, resumes from the stored position | `PostgresSinkTest.aBrokenConnectionLeavesNothingBehind` | ✅ |
| same batch written twice / out of order | no change; sessions only move forward | `PostgresSinkTest` | ✅ |
| out-of-order Interims, Accounting-On/Off | session rows equal the cluster's sessions | `BatchBuilderTest`, `PostgresExportIT`, `admin verify-export` | ✅ |
| exporter reads during an election | never past the commit position; restarts the replay when the recording is extended | `LogReplicaSpikeIT` | ✅ |
| re-export a range | `admin resync`; idempotent, same rows | `PostgresExportIT`, `ExportStateTest` | ✅ |
| three members migrate the schema at once | migrated once; `validate` refuses a changed or missing schema; `none` runs no DDL | `PostgresSinkTest` | ✅ |
| log grows without bound | purged below second-latest snapshot / slowest required sink / slowest member; a stopped member still catches up | `LogPurgeIT`, linux `PurgeIT` | ✅ |
| backlog drain rate | faster than intake for every storage variant | linux `ExportThroughputIT` | ✅ |
| 2M sessions with the exporter and its replica | members stay within 1 GiB | linux `OverloadIT` | ✅ |
