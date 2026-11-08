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
| leader killed before commit | no ACK; NAS retries; new leader commits once | e2e `LeaderFailoverIT` | 🔜 P1 |
| leader killed after commit, before response | NAS retries; duplicate answered, applied once | e2e `LeaderFailoverIT` | 🔜 P1 |
| gateway killed after commit | retry via other gateway answered as duplicate | e2e `GatewayFailoverIT` | 🔜 P1 |
| identical retransmit, same gateway | answered from response cache | e2e `RetransmitIT` | 🔜 P1 |
| retransmit with new Identifier / Acct-Delay-Time | cluster dedup, applied once | e2e `RetransmitIT` | 🔜 P1 |
| node restart | catches up from snapshot + log | e2e `NodeRestartIT` | 🔜 P1 |
| snapshot + restore with dedup state | duplicates still recognised | `AccountingServiceSnapshotTest` | 🔜 P1 |
| loss of quorum / partition | no ACKs while no majority; resumes after | e2e `QuorumLossIT` | 🔜 P2 |
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
