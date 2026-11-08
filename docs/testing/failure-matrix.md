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
| session capacity reached | new sessions rejected (no ACK), Stops still applied | `AccountingStateMachineTest.capacity` | ✅ |
| lost Stop | session removed after the idle timeout | `AccountingStateMachineTest.sweep…` | ✅ |
| duplicates in any position | never change the result | `DuplicatesPropertyTest` (jqwik) | ✅ |
| pending table or ring full | packet dropped, counted; NAS retransmits | `UdpAgentTest.fullPendingTableDrops` | ✅ |
| logging ring full | log events dropped and counted, caller never blocks | `NonBlockingLoggingIT` | ✅ |
| loss of quorum by network partition | no ACKs while no majority; resumes after | Linux network tests | 🔜 P2 |
| disk full / fsync failure | no ACK | Linux test | 🔜 P2 |
| power loss of one node | acknowledged records survive | Linux test with fsync | 🔜 P2 |
| sustained overload | bounded memory, drops instead of OOM | load test `--memory=1g` | 🔜 P2 |

## Export (Phase 3)

| Case | Expected behaviour | Test | Status |
|---|---|---|---|
| Postgres down | backlog grows on disk, replay after recovery, no duplicates | `PostgresSinkIT` (Testcontainers) | 🔜 P3 |
| required sink over `maxLag` | stop ACKing (`block`) | `LagPolicyIT` | 🔜 P3 |
| optional sink over `maxLag` | detach + alert, others continue | `LagPolicyIT` | 🔜 P3 |
| exporter crash mid-batch | resumes from checkpoint, idempotent | `ExporterRestartIT` | 🔜 P3 |
