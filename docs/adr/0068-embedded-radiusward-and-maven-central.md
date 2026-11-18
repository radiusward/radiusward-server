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
- **Maven Central under `io.radiusward`**, verified through `radiusward.io`; every production module is published
  with the prefix `radiusward-` because the embedded artifact depends on them. Supported API: the embedded, JUnit
  and client packages and the plug-in APIs; the rest may change in any release.
- Released with the project's version from the release workflow: sources, javadoc, GPG signatures.

## Consequences
- Developers need Java 25 and the JVM option for Agrona and Aeron; the page shows it, the server checks it.
- Every published module needs complete POM metadata and javadoc that builds; artifactIds change for the
  repository's own modules (directories and packages stay).
- The exporter and the identity stores accept instances besides `ServiceLoader` plug-ins; `export-api` and `auth-api`
  become the interfaces developers implement for both embedded use and production, so they stay compatible.
- A release needs the Central Portal token and the GPG key as repository secrets.
