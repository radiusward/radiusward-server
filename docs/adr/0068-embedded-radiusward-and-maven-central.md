# ADR 0068: An embedded radiusward for development, published on Maven Central

Status: Accepted (2026-11-18). Plan: [plans/embedded.md](../plans/embedded.md).

## Context
Developers of applications and devices that speak RADIUS want a server they can start from their tests with one
dependency, as RADIUS libraries for Java offer. radiusward runs only as separate processes or containers today; its
tests start members and RADIUS servers in one JVM (`LocalCluster`), but nothing of that is published, and the
artifacts carry names such as `server` and `common` that are too generic for a public repository.

## Decision
- **`radiusward-embedded`**: one cluster member and one RADIUS server in the developer's JVM, started by a builder
  with NAS entries, the developer's own identity stores and credential verifiers for authorization and their own
  sinks for accounting (instances of the public plug-in interfaces, so the same classes run as plug-ins in a
  cluster), shortcuts for tests and any setting;
  free ports, a temporary directory, fsync off; for development and tests only, said at start and in its description.
- **One member and one RADIUS server by default**, three members and several RADIUS servers on request, with controls to
  stop members, the leader and RADIUS servers, so failover can be tested in the JVM.
- **A real member, not a stand-in**: a single member commits alone, so answers come only after the commit and the
  production code decides everything; no second, in-memory implementation.
- **`radiusward-junit`** (JUnit 5 extension), **`radiusward-client`** (a RADIUS client for tests, grown from
  `TestPacket`) and **`radiusward-bom`** come with it.
- **EAP is testable end to end**: the client carries an EAP supplicant for every method radiusward offers (grown from
  the repository's test peers), and the embedded server creates a throwaway CA with server and client certificates
  for the TLS-based methods, so a test checks acceptance, authorization (reply items) and the keys a NAS receives.
- **Accounting is testable end to end**: the client acts as a NAS (sessions from Start to Stop, retransmissions,
  Accounting-On/Off, CoA received); a test reads the committed sessions and the exported records, and can pause the
  member to test a NAS or an application without acknowledgements.
- **Releases on Maven Central under `io.radiusward`** (verified through `radiusward.io`), **snapshots on GitHub
  Packages**; until the Central account exists, releases go to GitHub Packages too, with the same coordinates. Every
  production module is published with the prefix `radiusward-` because the embedded artifact depends on them. Supported API: the embedded, JUnit
  and client packages and the plug-in APIs; the rest may change in any release.
- Released with the project's version from the release workflow, in a job of its own: sources and javadoc jars, GPG
  signatures for Central.

## Consequences
- Developers need Java 25 and the JVM option for Agrona and Aeron; the page shows it, the server checks it.
- Every published module needs complete POM metadata and javadoc that builds; artifactIds change for the
  repository's own modules (directories and packages stay).
- The exporter and the identity stores accept instances besides `ServiceLoader` plug-ins; `export-api` and `auth-api`
  become the interfaces developers implement for both embedded use and production, so they stay compatible.
- `radiusward-embedded` depends on Bouncy Castle (bcprov, bcpkix, MIT licence) to make its throwaway CA and
  certificates for the TLS-based EAP methods: the JDK has no public API to build X.509 certificates, and hand-written
  certificate encoding would be ours to keep right. The server, the image and the chart do not depend on it.
- Snapshots need a GitHub token with `read:packages` to download; releases on Central need nothing. Publishing to
  Central needs the Central Portal token and the GPG key as repository secrets.
