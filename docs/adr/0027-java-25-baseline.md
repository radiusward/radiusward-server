# ADR 0027: Java 25 baseline

Status: Accepted (2026-11-09). Phase 5, work package 5.8, milestone 1 ([plans/phase-5-auth.md](../plans/phase-5-auth.md),
decision 3).

## Context
EAP-TLS, PEAP and TTLS derive their keys from the TLS session with the keying-material exporter (RFC 5705,
RFC 8446 §7.5). The JDK offers it from Java 25 on (`ExtendedSSLSession.exportKeyingMaterialKey/Data`,
JDK-8341346); before, only Bouncy Castle or reflection into JDK internals would do. The image and release builds
already ran Java 25; the code was compiled for 21.

## Decision
- The project compiles for **Java 25** (`maven.compiler.release`), the current long-term-support release. CI, the
  end-to-end, coverage, `linux-tests` and release jobs run Temurin 25; the image stays on `eclipse-temurin:25-jre`.
- Newer JDKs may build it (`--release 25`); runtime support is what CI and the image use: 25.

## Consequences
- `radiusward.jar` needs Java 25 or newer to run.
- Java 25's restrictions on `sun.misc.Unsafe` (warnings, JEP 471/498) apply to Agrona and Aeron; the
  `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` flag stays as it is.
