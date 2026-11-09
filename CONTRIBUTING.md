# Contributing to radiusward

Thanks for helping. This guide is the single source of truth for how the project is built and which
rules every change follows. Background and decisions: [docs/architecture.md](docs/architecture.md),
[docs/accounting-contract.md](docs/accounting-contract.md), [docs/adr](docs/adr).

Current state: **Phase 3** (export to PostgreSQL, sink plug-ins, log purge, metrics) is done; Phase 3b (more
sinks) and Phase 4 (Kubernetes) are next — see the [roadmap](docs/plans/roadmap.md).

## Setup

- JDK 21 (`export JAVA_HOME=$(/usr/libexec/java_home -v 21)` on macOS). CI also runs Java 25.
- No Docker needed for `./mvnw verify` and `-Pe2e`. Docker (Linux, or Colima on macOS) only for the image,
  compose and `-Plinux`. Details: [docs/operations/local-dev.md](docs/operations/local-dev.md),
  [docs/operations/docker.md](docs/operations/docker.md).
- Every JVM that loads Agrona/Aeron needs `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`
  (already set for tests via `${radiusward.jvm.args}` and in the `Add-Exports` manifest of runnable jars;
  add it to IDE run configurations).

## Commands

```bash
./mvnw verify                                   # build, unit + integration tests, coverage, format check
./mvnw -Pcoverage verify -Dradiusward.require.docker=true   # unit + integration coverage, module floors
./mvnw spotless:apply                           # format (palantir-java-format) + license headers
./mvnw -pl radius-codec -am test -Dtest=VendorFixtureTest -Dsurefire.failIfNoSpecifiedTests=false
./mvnw -pl radius-codec -am test -Dtest=VendorFixtureTest -Dfixtures.update=true -Dsurefire.failIfNoSpecifiedTests=false
                                                # rewrite fixture packet: lines after editing a fixture
./mvnw -Pbench -pl testing/benchmarks -am package -DskipTests && java -jar testing/benchmarks/target/benchmarks.jar
./mvnw -Pe2e verify                             # end-to-end tests against separate radiusward processes
./mvnw -Pinterop verify                         # also runs against a local FreeRADIUS (brew install freeradius-server)
scripts/run-local.sh start|status|demo-failover # local 3-node cluster + 2 gateways (docs/operations/local-cluster.md)
docker build -f deploy/docker/Dockerfile -t radiusward:dev .   # image (after ./mvnw install -DskipTests)
docker compose -f deploy/compose/compose.yaml up -d --wait     # compose stack (docs/operations/docker.md)
scripts/linux-tests.sh [TestClass]              # fault injection in containers (-Plinux, ~15 min)
java -jar tools/radclient/target/radclient.jar --help
scripts/update-dictionaries.sh <freeradius-commit-sha>   # refresh bundled dictionaries
```

## Modules

| Module | Purpose |
|---|---|
| `protocol` | SBE schema and generated codecs (gateway ↔ cluster, snapshots) |
| `common` | Config (properties + env), profiles, management HTTP server, non-blocking Log4j2 |
| `cluster-service` | `AccountingService` + deterministic `AccountingStateMachine`, `SessionStore`, snapshots |
| `cluster-node` | Launches a member (media driver, archive, consensus module, service, exporter, log purge) |
| `export-api` | Sink plug-in API, canonical attribute JSON, `SqlMigrations` |
| `exporter` | Committed-log reader, state-machine replica, lease, batching, plug-in loading |
| `sinks/postgres`, `sinks/file` | Built-in sinks |
| `auth-api` | Identity store and credential verifier plug-in API (`IdentityStore`, `CredentialVerifier`, `UserRecord`, `ItemParser`) |
| `stores/file`, `stores/sql`, `stores/ldap` | Built-in identity stores (users file; JDBC `radcheck` schema; LDAP/Active Directory with a bind verifier) |
| `verifiers/netlogon` | Credential verifier for Active Directory over Netlogon, pure Java (MS-CHAPv1/v2, PAP) |
| `testing/samba-ad` | Samba AD domain controller image for the LDAP and Netlogon tests |
| `gateway` | NIO UDP agent, cluster client agent, NAS registry, response cache, event keys |
| `distribution` | `radiusward.jar`: `cluster-node`, `gateway`, `radclient`, `admin`, `probe`, `cluster-tool` |
| `testing/test-harness` | `LocalCluster`, `DevCluster` |
| `testing/e2e-tests` | Process-based end-to-end tests (`-Pe2e`) |
| `testing/linux-tests` | Fault injection in containers with Testcontainers and LazyFS (`-Plinux`) |
| `radius-dictionary` | Dictionary model + FreeRADIUS-format parser (v3 + v4 subset), strict/lenient modes, `dictionary.d` overrides |
| `radius-dictionary-freeradius` | Bundled FreeRADIUS dictionaries (CC BY 4.0, unmodified, pinned commit) — resources only |
| `radius-codegen` | Generates constants classes and `AccountingAttributeExtractor` from the dictionaries |
| `radius-codec` | Zero-allocation packet view, attribute cursor, encoder, authenticators, Accounting-Response builder, Access-Request credentials (PAP, CHAP) and Access replies; generated `io.radiusward.radius.codec.attributes` |
| `tools/radclient` | CLI test client (`acct`, `replay`, `decode [--fixture]`, `load`), executable jar |
| `tools/admin-cli` | `AdminClient`; `admin state`, `admin verify-acks` (acknowledged events vs replicated state) |
| `testing/benchmarks` | JMH, only with `-Pbench` |
| `testing/coverage` | Aggregate coverage report and module floors, only with `-Pcoverage` |

## Project rules

- **No allocation on the hot path.** Receive → validate → verify → extract → respond uses flyweights over
  `DirectBuffer`, primitive collections, no `String`/boxing/lambdas capturing per packet.
  `HotPathAllocationIT` enforces it; keep it green and extend it when the hot path grows.
- **Return status codes, don't throw, for bad input.** Malformed packets are silently discarded (RFC 2865 §3).
- **State-machine rule changes are versioned:** a change to how an event is applied raises
  `AccountingStateMachine.STATE_VERSION` and keeps the old rule behind `machine.atLeast(n)`; the cluster activates
  it once every member runs it ([ADR 0005](docs/adr/0005-log-determinism-versioning.md)).
- **Determinism in the cluster service (Phase 1+):** cluster time only, no I/O, no randomness, no wall
  clock, no iteration over hash-ordered collections that affects output.
- **ACK boundary:** an Accounting-Response is sent only after the cluster reports the command committed.
  There is no Accounting-Reject; on failure stay silent.
- **Sinks** implement insert-if-absent events and update-only-if-newer sessions and contain no RADIUS logic
  ([writing-a-sink.md](docs/sinks/writing-a-sink.md)); tests that need Docker skip locally and fail in CI
  (`-Dradiusward.require.docker=true`).
- **Dependencies:** plain JDBC, never Hibernate/an ORM; plain NIO `DatagramChannel`, never Netty.
  The Maven enforcer bans both. Discuss any new runtime dependency before adding it.
- **Logging (Phase 1+):** Log4j2 async loggers; never log per packet on the hot path, never block the
  logging thread; parameterized, garbage-free calls only.
- **Docker stays optional for development:** `./mvnw verify` and `-Pe2e` never need it; only the image,
  compose and `-Plinux` do. Container and durability changes come with a `linux-tests` scenario.
- **Configuration** goes through `Config` (properties + `RADIUSWARD_*` env); document new keys in
  `docs/configuration.md`. `debug.*` keys only work with `debug.enabled=true`.
- **Gateways never block:** full rings or tables drop the packet (the NAS retransmits); never answer
  without a commit.
- **Dictionaries:** only FreeRADIUS files carrying the CC BY 4.0 header; never edit them by hand —
  use `scripts/update-dictionaries.sh`. Keep `NOTICE` / `THIRD-PARTY-LICENSES.md` in sync.
- **Generated code** lives in `target/generated-sources`, is never committed, and is driven by
  `radius-codec/src/main/codegen/hot-attributes.txt` (at most 64 fields until the presence mask is widened).
- **Every source file** carries the SPDX header (`./mvnw spotless:apply` adds it).
- **Tests with every change.** Coverage floors: `radius-codec` 90 % (generated code excluded),
  `radius-dictionary` 80 % in `./mvnw verify`; per module over unit + integration tests in
  `testing/coverage/floors.properties` (`-Pcoverage`, CI). Raise a floor when its module gains tests, never lower it.
- **Docs are part of the change:** update the relevant README / ADR / doc in the same commit; new
  decisions get an ADR.

## Conventions

- Java 21 language level, `io.radiusward` package root, palantir-java-format.
- Tests: JUnit 5 + AssertJ; jqwik for property-based fuzzing; `*IT` classes run under Failsafe
  (no JaCoCo agent — allocation measurements).
- Fixtures: `radius-codec/src/test/resources/fixtures/<vendor>/<event>.fixture` (format in
  [docs/testing/strategy.md](docs/testing/strategy.md)); currently synthetic.

## Submitting changes

1. Run `./mvnw spotless:apply verify` before pushing.
2. Commits: imperative subject line, explain the why in the body.
3. By contributing you agree that your contribution is licensed under the Apache License 2.0.
