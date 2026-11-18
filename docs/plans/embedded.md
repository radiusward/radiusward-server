# Plan: radiusward as a library for development and tests

Status: designed 2026-11-18, not started. Decision: [ADR 0068](../adr/0068-embedded-radiusward-and-maven-central.md).

## Goal

A developer adds one Maven dependency and starts a working RADIUS server inside their JVM: one cluster member and
one RADIUS server, authentication and accounting, ports chosen at start, everything gone on close. It is for
development and tests of applications and devices that speak RADIUS, not for production: no replication, no
fsync, a warning in the log. Production stays the cluster of three members described everywhere else.

```xml
<dependency>
    <groupId>io.radiusward</groupId>
    <artifactId>radiusward-embedded</artifactId>
    <version>0.1.0</version>
    <scope>test</scope>
</dependency>
```

```java
try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
        .client("127.0.0.1", "testing123")                // a NAS entry
        .user("alice", "secret")                          // users without a users file
        .identityStore(myStore)                           // or own Java logic (auth-api's IdentityStore)
        .onAccounting(record -> received.add(record))     // each committed accounting record
        .setting("auth.eap.methods", "peap,ttls")         // any key of docs/configuration.md
        .start()) {
    int auth = radius.authPort();
    int acct = radius.accountingPort();
}
```

## Artifacts (first version)

| Artifact | Contents |
|---|---|
| `radiusward-embedded` | `EmbeddedRadiusward` and its builder; depends on the server, a member and the users-file store |
| `radiusward-junit` | `RadiuswardExtension` for JUnit 5: started per class or per test, ports and the client injected |
| `radiusward-client` | a RADIUS client for tests: Access-Request with PAP, CHAP, MS-CHAPv2, Accounting-Request, Status-Server, CoA answers; retransmission and response verification; the packet builder that `TestPacket` is today; an **EAP supplicant** that runs whole conversations (below) |
| `radiusward-bom` | the versions of every published artifact, imported once |

Every module these depend on is published too, so all production modules go to Maven Central under
`io.radiusward` with the prefix `radiusward-`:

| Module | Artifact |
|---|---|
| `units`, `common`, `protocol` | `radiusward-units`, `radiusward-common`, `radiusward-protocol` |
| `radius-codec`, `radius-dictionary`, `radius-dictionary-freeradius` | `radiusward-codec`, `radiusward-dictionary`, `radiusward-dictionaries` |
| `cluster-service`, `cluster-node`, `exporter`, `export-api` | `radiusward-cluster-service`, `radiusward-cluster-node`, `radiusward-exporter`, `radiusward-export-api` |
| `server`, `auth-api` | `radiusward-server`, `radiusward-auth-api` |
| `sinks/*`, `stores/*`, `verifiers/netlogon` | `radiusward-sink-file`, `-sink-postgres`, `-sink-radius`, `radiusward-store-file`, `-store-sql`, `-store-ldap`, `radiusward-verifier-netlogon` |
| `tools/radclient`, `tools/admin-cli` | `radiusward-radclient`, `radiusward-admin-cli` |

Not published: `radius-codegen` (build time only), `distribution` (the runnable jar stays on the GitHub release and
in the image) and `testing/*`; `testing/test-packets` becomes part of `radiusward-client`.

**Public API.** Supported and kept compatible within a minor version: `io.radiusward.embedded`,
`io.radiusward.junit`, `io.radiusward.client`, and the plug-in APIs `auth-api` and `export-api`. Everything else is
published only as their dependency and may change in any release (stated in each artifact's description and the
page). Until 1.0, minor versions may change the public API too, with a note in the release.

## Design

- **One real member, not a stand-in.** The embedded server starts a cluster of one member with its media driver,
  archive and consensus module, and one RADIUS server, as `LocalCluster` does in the tests. A single member commits
  alone, so Accounting-Responses still come only after the commit and the same code decides everything. A lighter
  in-memory variant would answer faster but behave differently and be a second code path to keep right.
- **Small and temporary.** A temporary directory (or one the developer names), fsync off (`archive.file.sync.level=0`),
  short Aeron terms and a small session capacity, so the JVM needs little memory; all ports free unless set.
  Startup time and memory are measured and documented (target: under 2 s, under 256 MB heap and direct memory).
- **Users.** `user(name, password, attributes...)` writes a users file in the temporary directory and uses the
  file store, so the same check and reply items work as in production. `identityStore(...)` registers an object
  instead of a plug-in found by `ServiceLoader`; `auth-api` gets a way to pass an instance.
- **Accounting callback.** An in-process sink of the exporter (export-api) given as an object, so the callback
  sees exactly what a sink sees after the commit: events and session snapshots. The exporter gets a way to take a
  sink instance besides the plug-ins it loads.
- **EAP.** `eap("peap", "ttls", "tls", ...)` turns methods on (`auth.eap.methods`). The TLS-based methods need a
  server certificate: unless the developer gives one, the embedded server creates a throwaway CA, a server
  certificate and, on request, client certificates in its temporary directory, and exposes the CA
  (`radius.ca()`, `radius.clientCertificate("alice")`) so the supplicant can trust the server and EAP-TLS can log in.
  EAP-SIM/AKA subscribers are users with their SIM keys (`simUser(imsi, ki, opc)`); sequence numbers come from the
  embedded member as in production.
- **Settings.** `setting(key, value)` takes any key of [configuration.md](../configuration.md); the builder's own
  methods are shortcuts. Unknown keys fail as in a configuration file.
- **Lifecycle.** `start()` returns once the member is leader and the RADIUS server connected; `close()` stops both
  and deletes the temporary directory. Several instances can run in one JVM (each with its own Aeron directories
  and ports), so tests can run in parallel.
- **Not for production.** A warning at start, the artifact's description and the page say so; there is no
  replication and no durability.
- **Requirements for the developer.** Java 25, and the JVM option `--add-exports
  java.base/jdk.internal.misc=ALL-UNNAMED` that Agrona and Aeron need: the page shows it for Surefire, Failsafe,
  Gradle and IDEs; the embedded server checks it at start and fails with a message naming the option.

## Testing EAP

A NAS only relays EAP; what a test needs is the device's side. `radiusward-client` carries an EAP supplicant grown
from the peers the repository's tests already use (`PeapPeer`, `TtlsPeer`, `TeapPeer`, `EapTlsClient`, the EAP-pwd
and EAP-SIM/AKA peers): it sends EAP-Message in Access-Requests, follows State and Access-Challenges to the end,
and returns the outcome with what the test wants to check.

```java
EapResult result = radius.client().eap(EapLogin.peap("alice", "secret")       // PEAP with inner MS-CHAPv2
        .trust(radius.ca())
        .outerIdentity("anonymous@example.org"));
assertThat(result.accepted()).isTrue();
assertThat(result.reply().string("Class")).isEqualTo("gold");                 // reply items, VLAN, Session-Timeout
assertThat(result.msk()).isEqualTo(result.serverMppeKeys());                  // the keys a Wi-Fi AP would get
```

| Method | Supplicant | What a test can check |
|---|---|---|
| EAP-MD5, EAP-GTC | yes | accept, reject, reply items |
| PEAP (MS-CHAPv2, GTC, TLS inside), crypto-binding | yes | outer and inner identity, reply items, MPPE keys equal to the client's MSK, session resumption |
| EAP-TTLS (PAP, CHAP, MS-CHAP, MS-CHAPv2, EAP inside) | yes | as PEAP |
| EAP-TLS | yes, with a certificate from the embedded CA or the developer's | identity against the certificate, revocation (CRL), resumption |
| TEAP (Basic-Password-Auth, inner EAP), EAP-pwd | yes | as above |
| EAP-SIM, EAP-AKA, EAP-AKA′ | yes, a simulated SIM from Ki and OPc | pseudonyms, fast re-authentication, sequence numbers through the member |

Authorization is tested the same way for every method: the users, groups, check and reply items, rules,
Simultaneous-Use and IP pools of the embedded server decide, and the result carries the Access-Accept's attributes
or the reject. A test can also drive single rounds (`EapConversation.next(...)`) to check malformed or unexpected
answers, and the page shows how to run a real supplicant (`eapol_test` in its container image) against the
embedded server for interoperability.

## Testing accounting

Accounting is where radiusward differs from a plain RADIUS library: an Accounting-Response means the record is
committed, retransmissions are counted once, and sessions live in the replicated state. A test sees all of it.

```java
RadiusClient nas = radius.client();
AccountingSession s = nas.session("s-1").user("alice").callingStationId("aa-bb-cc-dd-ee-ff");
assertThat(nas.send(s.start())).isAcknowledged();
nas.send(s.interim(Duration.ofMinutes(5), 1_000_000, 4_000_000));     // session time, input and output octets
nas.send(s.interim(Duration.ofMinutes(5), 1_000_000, 4_000_000).delay(3)); // a NAS retransmission: counted once
nas.send(s.stop(Duration.ofMinutes(10), 2_000_000, 8_000_000, "User-Request"));

assertThat(radius.session("s-1")).hasState(STOPPED).hasSessionTime(Duration.ofMinutes(10));
assertThat(radius.activeSessions("alice")).isEmpty();
assertThat(received).extracting(AccountingRecord::statusType).containsExactly(START, INTERIM, STOP);
```

- **The NAS side**: `AccountingSession` builds Start, Interim-Update, Stop, Accounting-On and -Off with the usual
  attributes (session time, octets with Gigawords, Event-Timestamp, Acct-Delay-Time, terminate cause, NAS and device
  identity, vendor attributes); `send` retransmits as a NAS does and verifies the Response Authenticator. Recorded
  packets (the vendor fixtures' format, `radclient decode --fixture`) can be replayed.
- **What the server committed**: `session(id)`, `activeSessions(user)` and `sessions()` read the replicated state as
  the CoA API does; `onAccounting(...)` receives the exported events and session snapshots in commit order, the way
  a sink sees them, and `awaitAccounting(n)` waits for them.
- **Duplicates and order**: the same event retransmitted, sent with another Identifier or Acct-Delay-Time, or a Stop
  before its Start are applied once, and the test can assert that ([accounting contract](../accounting-contract.md)).
- **Without the cluster**: `radius.pauseCluster()` stops the member, so the NAS gets no Accounting-Response and has to
  buffer and retry; `resumeCluster()` brings it back and the retries are applied once. This is how a developer tests
  the NAS's or the application's behaviour when accounting is not acknowledged.
- **Sessions ending on their own**: Accounting-On/Off from the NAS, and the idle timeout (`setting("cluster.idle.timeout",
  "5s")` or the NAS entry's) with `awaitSessionGone(id)`.
- **Simultaneous-Use and limits**: accounting and authentication together, as in production: a second device of a
  user limited to one is rejected until the first one's Stop.
- **Export to a real database**: the sink settings (`sink.<name>.*`) work as in production, e.g. PostgreSQL in a
  test container, so an application reading `accounting_session` or `radacct` can be tested against real rows.
- **CoA and Disconnect**: the client can listen as a NAS (`nas.listenForCoa(...)`); `radius.disconnect(user)` and
  `radius.coa(user, attributes)` send through the embedded server's CoA path, so a test checks what its NAS receives.

## Publishing on Maven Central

- **Namespace** `io.radiusward`, verified through a DNS TXT record on `radiusward.io` in the Central Portal.
- **Release build** (`-Prelease`): sources and javadoc jars, GPG signatures, POM metadata (name, description, URL,
  Apache-2.0 licence, SCM, developers) inherited from the parent, `NOTICE` and the dictionaries' CC BY 4.0 licence in
  every jar that carries them; published with the Central Portal's Maven plugin.
- **CI**: `release.yml` on a version tag also deploys to Central with secrets for the Portal token and the GPG key;
  snapshots of `main` optionally to the Portal's snapshot repository.
- The version stays the project's version: the jars, the image and the chart are released together.

## Documentation

- README: a section "Use it as a library (development and tests)" with the dependency, the server example, the JUnit
  example, the client example, an EAP example and the JVM option.
- The page has a section "Testing accounting": sessions from Start to Stop, retransmissions counted once, the
  committed state and the exported records, the NAS without acknowledgements, Accounting-On/Off and idle timeouts,
  export to a database, CoA and Disconnect.
- The page has a section "Testing EAP": methods, the throwaway CA and client certificates, checking reply items and
  keys, SIM subscribers, single rounds, and a real supplicant.
- Website: a page `/docs/develop/embedded/` in the same shape as above, linked from the start pages.
- `docs/operations/release.md`: how a release reaches Central.

## Work packages

| # | Work | Done when |
|---|---|---|
| E1 | Rename artifactIds to `radiusward-*`; POM metadata; `-Prelease` profile (sources, javadoc, signing); javadoc builds for every published module | `./mvnw -Prelease verify` passes locally with a test key |
| E2 | `radiusward-client` from `TestPacket` and `FakeNas`: client, packet builder, auth helpers | its tests; the repository's tests use it |
| E2a | Accounting in `radiusward-client`: `AccountingSession` (Start, Interim, Stop, On, Off), retransmission, fixture replay, a CoA listener | its tests; the e2e and harness tests use it |
| E2b | The EAP supplicant in `radiusward-client` from the test peers: every method above, results with reply items and keys, single rounds | each method against the embedded server; the repository's EAP tests use it |
| E3 | Sink and identity-store instances besides plug-ins (exporter, auth-api) | unit tests |
| E4 | `radiusward-embedded`: builder, single member, users, EAP with the throwaway CA, SIM users, accounting callback and state queries, pausing the member, CoA, settings, lifecycle, the JVM-option check | an IT from a plain Maven project outside the reactor; startup and memory measured |
| E5 | `radiusward-junit` | tests per class and per test, parallel |
| E6 | `radiusward-bom`; release workflow to Central; README, website page, release doc | `0.1.0` resolvable from Central in an empty project |

## What the maintainer does

- Register `radiusward.io` and add the TXT record the Central Portal shows.
- Create the Central Portal account (sign in with GitHub), verify the namespace, create a user token.
- Create a GPG key for signing, publish its public key to a key server.
- Add the repository secrets: Portal token user and password, the GPG private key and its passphrase.
