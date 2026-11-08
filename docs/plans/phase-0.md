# Phase 0 build plan: codec foundation, docs, tooling

Status: **done** (2026-11-07) · Created: 2026-11-07 · Report: [below](#phase-0-report)

## Goal

Phase 0 delivers what everything else stands on: the repo, the RADIUS codec, the dictionaries
plus code generation, all docs, the contributor guide, and CI. **No cluster or gateway yet.** Those come in
Phase 1. Phase 0–1 runs entirely locally on macOS, without Docker (see ADR 0009).

## Exit criteria

1. `./mvnw verify` passes on Java 21 and Java 25, locally and in GitHub Actions.
2. `radius-codec` parses and encodes Accounting-Request and Accounting-Response correctly.
   Checked against RFC test vectors, against aaa4j as a reference implementation, and by fuzz tests.
3. The hot path is **verified allocation-free** by a test, not just by design.
4. All six vendor dictionaries load (Cisco, Juniper, MikroTik, Huawei, Meraki, Ruckus).
   The generated accessors compile and are tested.
5. All READMEs, docs/ADRs, the contributor guide (`CONTRIBUTING.md`, `AGENTS.md`), `NOTICE` and `THIRD-PARTY-LICENSES.md` are in place.
6. `tools/radclient` sends real UDP packets. If FreeRADIUS is installed via Homebrew, an optional
   interop test runs against it.

## Fixed inputs (decisions already made)

- **Build:** Maven multi-module, compiled for Java 21 (`release 21`), tests also on Java 25.
  CI is GitHub Actions; release images are built on Java 25 from Phase 2.
- **Package root:** `io.radiusward`. **License:** Apache-2.0.
- **Dependencies:** no Hibernate, no Netty (UDP uses plain NIO `DatagramChannel`).
- **Dictionaries:** FreeRADIUS format, bundled from FreeRADIUS **master** at a pinned commit
  (`share/dictionary/radius/`). In the v3.2.x branch `dictionary.meraki` has no CC-BY header;
  master has it on all six vendors. Only files that carry the CC-BY 4.0 header are used.
  The parser supports v3 syntax plus the v4 subset. Operators can mount their own files in
  `/etc/radiusward/dictionary.d/`.
- **Code generation:** at build time for the attributes on the hot path. Everything else uses the
  runtime dictionary.

## Repo after Phase 0

```text
radiusward/
├── pom.xml                         # parent: dependency/plugin management, profiles
├── mvnw, .mvn/wrapper/             # Maven 3.9.x wrapper
├── .github/workflows/ci.yml        # matrix: Java 21 + 25, mvn verify (no images yet)
├── .editorconfig, .gitignore
├── LICENSE (Apache-2.0), NOTICE, THIRD-PARTY-LICENSES.md
├── README.md, CONTRIBUTING.md, AGENTS.md, SECURITY.md
├── radius-dictionary/              # model + FreeRADIUS parser (v3 + v4 subset), runtime lookup
├── radius-dictionary-freeradius/   # bundled CC-BY files (pinned master commit) + LICENSE-CC-BY-4.0
├── radius-codegen/                 # CLI: dictionaries + hot-attribute list → Java sources
├── radius-codec/                   # flyweights, encoder, authenticators, generated accessors
├── tools/radclient/                # Java CLI: build/send Accounting-Request, print response
├── testing/benchmarks/             # JMH for codec (not part of the default build)
└── docs/
    ├── architecture.md
    ├── accounting-contract.md
    ├── dictionaries.md
    ├── protocol.md                 # SBE: draft, finalised in Phase 1
    ├── adr/0001…0009
    ├── operations/local-dev.md
    ├── testing/{strategy.md, failure-matrix.md}
    └── plans/{phase-0.md, roadmap.md}
```

Packages: for example `io.radiusward.radius.codec`, `io.radiusward.radius.dictionary`,
`io.radiusward.tools.radclient`.

## Work steps

### P0.1: Build skeleton (size S)

- `git init`, Maven wrapper, parent POM with `<maven.compiler.release>21</maven.compiler.release>`.
- **Dependency management:** Agrona (kept at the version Aeron uses); JUnit Jupiter, AssertJ and
  jqwik for tests; JMH; aaa4j-radius **test-only** as a reference implementation. All pinned to the
  latest stable versions after checking Maven Central.
- **Plugins:**
  - Surefire for unit tests, Failsafe for integration tests (`*IT`).
  - JaCoCo for coverage.
  - **Spotless** with palantir-java-format.
  - **license-maven-plugin**: SPDX `Apache-2.0` header on every source file, dictionaries excluded.
  - **maven-enforcer**: Java 21 or newer, Maven 3.9 or newer, dependency convergence,
    **bans `org.hibernate*` and `io.netty*`**.
- **Profiles:** `e2e` (used from Phase 1), `interop` (needs a local FreeRADIUS), `bench`.
- **CI:** `ci.yml` runs `./mvnw -B verify` on Temurin 21 and 25.
- ✅ **Done when:** an empty multi-module build is green locally and in CI on both Java versions.

### P0.2: Bundle the dictionaries (size S)

- Copy the needed files from FreeRADIUS master at **one pinned commit**: the root `dictionary`,
  the RFC files, `dictionary.{cisco,juniper,mikrotik,huawei,meraki,ruckus}`, plus anything they
  `$INCLUDE`.
- Add `scripts/update-dictionaries.sh <sha>`. It **fails if any copied file lacks the CC-BY
  header**.
- Add `LICENSE-CC-BY-4.0.txt` in the module, plus entries in `NOTICE`, `THIRD-PARTY-LICENSES.md`
  and the README section "Third-Party Resources", including the commit SHA.
- ✅ **Done when:** the script is reproducible, every file has a CC-BY header, and the
  attribution is complete.

### P0.3: Dictionary model and parser (size M)

- **Model:**
  - `Dictionary`, `VendorDef` (id, `format=t,l`), `AttributeDef` (vendor, type, name, data type,
    flags such as `encrypt` / `has_tag` / `concat`), `ValueDef`.
  - Lookup by `(vendorId, type)` goes through a primitive `Long2ObjectHashMap` and is
    allocation-free at runtime. Name maps are only used at startup.
- **Parser:**
  - **v3:** `ATTRIBUTE`, `VALUE`, `VENDOR` (+format), `BEGIN-VENDOR` / `END-VENDOR`,
    `$INCLUDE` / `$INCLUDE-`.
  - **v4:** `PROTOCOL`, `BEGIN-PROTOCOL` / `END-PROTOCOL`, `END-VENDOR <name>`, `ALIAS`,
    `MEMBER` / `STRUCT`.
  - **Unknown keywords:** in lenient mode (operator files) they're skipped with a warning plus
    file and line number. Strict mode (our bundled set, in tests) fails on them.
  - Data types: `integer`, `integer64`, `string`, `octets`, `ipaddr`, `ipv6addr`, `ipv6prefix`,
    `date`, `byte`, `short`, `signed`, `ether`, `ifid`, `combo-ip`, `tlv`, `vsa`. `struct` is
    parsed but not yet decoded in depth.
- **Loader:**
  - The bundled set comes from the classpath. After that, `/etc/radiusward/dictionary.d/` is
    loaded from the filesystem; the path is configurable.
  - Later definitions override earlier ones and log a warning. A conflicting attribute number
    with a different type is an error.
- ✅ **Done when:** the bundled set loads in strict mode; each keyword has unit tests, including
  `$INCLUDE` cycles and error messages with line numbers; a v3.2 operator test file loads in
  lenient mode.

### P0.4: Packet codec (size L): the core of Phase 0

- **`RadiusPacket` flyweight** over `DirectBuffer` exposes code, identifier, length and
  authenticator. An `AttributeCursor` walks the attributes (`next()`, `vendorId()`, `type()`,
  `valueOffset()`, `valueLength()`) without creating objects.
- **VSA support (attribute 26):** vendor ID, then sub-attributes, respecting the vendor's
  `format=t,l`.
- **RFC 6929 extended attributes (241–246):** the cursor recognises and skips them correctly;
  full decoding comes later.
- **Validation per RFC 2865 §3:**
  - Length must be 20–4096 bytes.
  - Bytes beyond `Length` are ignored. A packet shorter than its `Length` is rejected.
  - Each attribute must have a length of at least 2 and fit inside the packet.
  - Errors come back as **status codes** (e.g. `MALFORMED_ATTRIBUTE`), not exceptions, on the
    hot path.
- **`RadiusPacketEncoder`** writes into a `MutableDirectBuffer`. Its main job is building the
  Accounting-Response.
- **Authenticators:**
  - Accounting-Request check: MD5(Code+ID+Length+16×0+Attrs+Secret).
  - Response: MD5(Code+ID+Length+RequestAuth+Attrs+Secret).
  - `Message-Authenticator` (HMAC-MD5) check and generation.
  - One reused `MessageDigest` / `Mac` per thread, using the `digest(byte[], off, len)` variants,
    so nothing is allocated.
  - The secret is compared in constant time.
- **Value readers:** int, long, IPv4/IPv6, date, string (as offset and length, no `String` on the
  hot path). **64-bit octet counters**: `Acct-Input-Octets` + `Acct-Input-Gigawords` combined
  into one `long`; the same for Output.
- ✅ **Done when:** the RFC 2865 §7 test vectors pass; differential tests against aaa4j pass
  (same bytes give the same parse result, and our encoding gives the same packet); jqwik fuzz
  tests show the parser never throws on random or truncated bytes and never reads outside the
  buffer; coverage is at least 90%.

### P0.5: Code generation for hot attributes (size M)

- **`radius-codegen`** is a small CLI on top of `radius-dictionary`. Inputs are the dictionaries
  plus `radius-codec/src/main/codegen/hot-attributes.txt`, for example:

  ```text
  0        Acct-Status-Type        -> statusType
  0        Acct-Session-Id         -> sessionId
  0        Acct-Input-Gigawords    -> inputGigawords
  9        Cisco-AVPair            -> ciscoAvPair      # repeated
  14988    Mikrotik-Rate-Limit     -> mikrotikRateLimit
  ```

- It runs in `radius-codec` during `generate-sources`, via `exec-maven-plugin` with in-reactor
  plugin dependencies. The output goes to `target/generated-sources` and is never checked in.
- **What gets generated:**
  1. One constants class per vendor and RFC: `Rfc2866`, `Cisco`, `Juniper`, `Mikrotik`,
     `Huawei`, `Meraki`, `Ruckus`. Each holds the vendor ID, attribute numbers and enumerated
     `VALUE` constants (e.g. `ACCT_STATUS_TYPE_START = 1`).
  2. **`AccountingAttributeExtractor`**: a single pass over the packet into a reusable
     `AccountingFields` object. It holds primitive fields plus offset and length pairs for
     strings, and handles repeated attributes such as `Cisco-AVPair` in a fixed-size slot array.
- ✅ **Done when:** generation is reproducible (same input, byte-identical output); there are
  extractor tests per vendor; unknown attributes in the list break the build with a clear error.

### P0.6: Vendor test packets (size M)

- `src/test/resources/fixtures/<vendor>/` holds hex files plus an expected result for Start,
  Interim-Update and Stop for each of the six vendors. They include typical VSAs (Cisco-AVPair,
  Huawei input/output peak rate, MikroTik rate limit, Ruckus SSID/user group, Meraki device name)
  plus gigaword overflow.
- At first these are **built from vendor docs and dictionaries**, clearly marked "synthetic".
  They get replaced with real captures as soon as we have any; `docs/testing/strategy.md`
  describes how to capture and anonymise them.
- The same fixtures feed the dedup and e2e tests in Phase 1.
- ✅ **Done when:** each vendor's fixtures parse, extract and round-trip correctly.

### P0.7: Allocation and performance tests (size S)

- **Allocation test** (Failsafe IT): after warm-up, run 1M parse plus extract plus authenticator
  checks, measured with `com.sun.management.ThreadMXBean#getThreadAllocatedBytes`, and assert
  **≈0 bytes per packet**.
- **JMH** in `testing/benchmarks` (`-Pbench`) measures parse, extract and authenticator
  throughput, and records the baseline in `docs/testing/strategy.md`.
- ✅ **Done when:** the allocation test is green in CI and the benchmark numbers are documented.

### P0.8: `tools/radclient` (size S)

- A Java CLI on top of `radius-codec` using NIO `DatagramChannel`:

  ```bash
  radclient acct --server 127.0.0.1:1813 --secret testing123 \
           --vendor cisco --status start --session-id abc123 [--retries 3 --timeout 3s]
  radclient replay fixtures/huawei/interim.hex ...
  ```

- Built as an executable jar; reused for the Phase 1 demos and the e2e tests.
- **Optional interop test (`-Pinterop`):** if `radiusd` from Homebrew is installed, the test
  starts it with a minimal config. `radclient` sends all fixtures to it and checks the
  Accounting-Response authenticators. Without FreeRADIUS installed, the test is skipped.
- ✅ **Done when:** `radclient` works against the interop server and has unit tests for its
  argument parsing.

### P0.9: Documentation (size M), written alongside the code

| File | Content | Status after Phase 0 |
|---|---|---|
| `README.md` (root) | What it is, architecture overview, quickstart, module map, license, Third-Party Resources | Complete for Phase 0 |
| `README.md` per module | Purpose, public API, dependencies, examples | Complete |
| `CONTRIBUTING.md` + `AGENTS.md` | Commands (`./mvnw verify`, `-Pe2e`, `-Pinterop`, `-Pbench`), module map, project rules | Complete |
| `docs/architecture.md` | C4 context and container views, data flow NAS → gateway → cluster → sinks, threading model | Complete (target picture) |
| `docs/accounting-contract.md` | What an ACK guarantees: majority commit + fsync; silent drop on failure; dedup semantics | Complete |
| `docs/dictionaries.md` | Bundled set + commit SHA, `dictionary.d` override, v3/v4 support, CC-BY, update script | Complete |
| `docs/protocol.md` | SBE messages (AccountingCommand, AccountingCommitted, ExportCheckpoint), versioning rules | Draft |
| `docs/adr/0001` … `0009` | See list below | Complete |
| `docs/operations/local-dev.md` | Setup on macOS, build, IntelliJ, sysctl for UDP buffers, optional FreeRADIUS | Complete |
| `docs/testing/strategy.md` | Test pyramid, fixtures, allocation tests, JMH, e2e plan | Complete |
| `docs/testing/failure-matrix.md` | Every failure case → expected behaviour → test (Phase 1+ marked "planned") | Complete as a plan |
| `docs/plans/roadmap.md` | Phases 0–5; deployment (compose/Helm/systemd) marked "planned" | Complete |

**ADRs:**

1. 0001 Aeron Cluster
2. 0002 ACK boundary
3. 0003 Event key and per-session dedup
4. 0004 Memory budget and profiles
5. 0005 Log determinism and versioning
6. 0006 NIO UDP transport
7. 0007 Sink SPI and lag policy
8. 0008 Dictionaries, licensing and code generation
9. 0009 Local-first development (no Docker in Phase 0–1)

**Project rules (`CONTRIBUTING.md`):**

- No allocation on the hot path (flyweights, no `String` / boxing).
- The cluster service stays deterministic: cluster time only, no I/O.
- NIO, not Netty; no Hibernate.
- No Docker in Phase 0–1.
- Dictionaries only with a CC-BY header, plus attribution.
- An SPDX header in every file.
- Tests with every change.

✅ **Done when:** every link works and every doc has had a review pass.

### P0.10: Phase review (size S)

- Check every exit criterion, and append a short "Phase 0 report" to this file with the benchmark
  figures and what's still open.
- Plan Phase 1 in detail on the basis of these findings.

## Order and dependencies

```text
P0.1 ─┬─► P0.2 ─► P0.3 ─► P0.5 ─┐
      │                         ├─► P0.6 ─► P0.7 ─► P0.8 ─► P0.10
      └─► P0.4 ─────────────────┘
P0.9 (docs) runs alongside: ADRs + contributor guide first, module READMEs with each step
```

P0.3 (dictionaries) and P0.4 (codec cursor and authenticators) can be built in parallel.
Code generation needs both.

## Risks

| Risk | Handling |
|---|---|
| The v4 dictionary syntax has constructs beyond `ALIAS` / `MEMBER` | Strict mode on the bundled set finds them right away. Implement what's missing or skip it in a documented way. |
| Synthetic fixtures don't match real devices | Mark them clearly. Capture guide in place. Replace with real captures before Phase 2. |
| `MessageDigest` allocates internally after all | The allocation test catches it. Fallback: our own MD5 over `DirectBuffer` (~150 lines). |
| A FreeRADIUS update removes headers or licenses | The update script fails the build. |

## Defaults chosen in this plan

- Formatter: palantir-java-format.
- SPDX short header instead of the full Apache text.
- `radclient` is part of Phase 0, so the codec gets verified against real FreeRADIUS early.
- Full e2e test infrastructure (the process launcher for cluster JVMs) starts in Phase 1.

---

## Phase 0 report

Completed 2026-11-07. `./mvnw clean verify` on JDK 21: **BUILD SUCCESS, 166 tests, 1 skipped**
(the FreeRADIUS interop test — `radiusd` is not installed on the development machine). The same
build also passes on JDK 27. Java 25 is covered by the CI matrix (`.github/workflows/ci.yml`), which
has not run yet because the repository has no GitHub remote.

### Exit criteria

| # | Criterion | Result |
|---|---|---|
| 1 | `./mvnw verify` green on Java 21 and 25, locally and in CI | ✅ Java 21 locally (also 27). ⏳ Java 25 + CI: workflow in place, runs once pushed to GitHub |
| 2 | Codec correct: RFC vectors, aaa4j differential, fuzzing | ✅ RFC 2865 §7.1 response authenticator, RFC 2104/2202 HMAC vectors, aaa4j both directions + 300 random attribute sets, 8,000 fuzz cases per run |
| 3 | Hot path verified allocation-free | ✅ `HotPathAllocationIT`: 1M packets (validate, verify Request Authenticator + Message-Authenticator, extract, encode + sign response) allocate < 4 KB in total |
| 4 | Six vendor dictionaries load, generated accessors tested | ✅ whole bundled set loads in strict mode; 18 fixtures (Cisco, Juniper, MikroTik, Huawei, Meraki, Ruckus × Start/Interim/Stop) |
| 5 | READMEs, docs/ADRs, contributor guide, NOTICE, THIRD-PARTY-LICENSES | ✅ all written; relative links checked |
| 6 | radclient sends real UDP; optional interop | ✅ loopback UDP tests (answer, retransmit, timeout, Message-Authenticator). ⏳ interop test written, not executed (no local FreeRADIUS) |

Coverage (line): `radius-codec` 98.5 % (generated code excluded), `radius-codegen` 95 %,
`radius-dictionary` 81 %.

### Benchmarks

Apple M4 Pro, JDK 21, ~200 byte Cisco interim update: full receive path **~2.2 M packets/s per core**
(validate ~63 M/s, extract ~13 M/s, encode + sign ~9.6 M/s, MD5 verify ~3.4 M/s). Details in
[testing/strategy.md](../testing/strategy.md#benchmark-baseline-phase-0).

### Deviations from the plan

| Plan | What was done | Why |
|---|---|---|
| Bundle the RFC files + six vendor files | Bundled the **whole** CC BY 4.0 set (249 files, ~190 vendors); `dictionary.ingate` excluded | Every vendor works out of the box, and strict-mode loading of the full set is a much stronger parser test |
| license-maven-plugin for headers | Spotless `licenseHeader` | One plugin instead of two; same SPDX header check |
| Latest JUnit | JUnit 5.14.4 | Aligns with jqwik 1.10.2's JUnit Platform (dependency convergence) |
| — | Every JVM needs `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` | Agrona 2.x (and Aeron) require it; set for tests, in jar manifests and documented in CONTRIBUTING.md |
| Coverage ≥ 90 % for the codec | Generated `attributes` package excluded from the check (still reported) | Covering every generated branch would only re-test the template; the generator has its own tests |

### Findings worth knowing

- **FreeRADIUS master uses v4 dictionary syntax** (`ALIAS`, `MEMBER`, `struct`/`union`, relative numbers,
  scoped names such as `Cisco` → `AVPair`); the parser supports it alongside v3.
- **aaa4j-radius quirk:** its decoder checks an Accounting-Request's Message-Authenticator with the real
  authenticator, while its encoder (and FreeRADIUS) use sixteen zero bytes. Our implementation follows
  FreeRADIUS; the differential tests compare against aaa4j's encoder only.
- **Juniper MX subscriber management** sends ERX/Unisphere attributes (vendor 4874), not Junos (2636).
  They are decoded by the runtime dictionary; add them to `hot-attributes.txt` if MX BNGs are in scope.
- All 18 fixtures are **synthetic**; replace them with anonymised captures before Phase 2
  (guide in [testing/strategy.md](../testing/strategy.md)).

### Open items carried into Phase 1

- Run CI once the repository is on GitHub (needs the GitHub owner/org — also the GHCR path).
- Optionally `brew install freeradius-server` and run `./mvnw -Pinterop verify`.
- ~~Decide whether Juniper ERX (4874) attributes join the hot list.~~ Done 2026-11-08: 12 ERX fields,
  `Unisphere` constants class, 3 fixtures, radclient preset `juniper-erx` (61 of 64 fields used).
- Phase 1 detailed plan: SBE `protocol` module, cluster node + AccountingService, gateway agents,
  NAS registry, local harness/dev mode/`run-local.sh`, `testing/e2e-tests`.
