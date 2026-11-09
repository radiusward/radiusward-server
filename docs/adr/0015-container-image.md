# ADR 0015: Container image and runtime layout

Status: Accepted (2026-11-08). Phase 2.

## Context
Phase 2 brings Docker and compose (ADR 0009); Phase 4 brings Kubernetes. One artefact should serve every
deployment, stay small and run without root.

## Decision
- **One image** for all components, `ghcr.io/radiusward/radiusward-server`, entrypoint `radiusward`:
  `cluster-node`, `gateway`, `radclient`, `admin`, `probe`, `cluster-tool`, `version`.
- Base `eclipse-temurin:25-jre-noble` (multi-arch, glibc, maintained). The jar is built with JDK 25 for
  bytecode level 25 since Phase 5.8 (ADR 0027); before that it was 21.
- Runs as **uid/gid 10001** (`radiusward`), no root, no extra capabilities.
- Layout: `/opt/radiusward/radiusward.jar`, licences next to it; data in the `VOLUME /var/lib/radiusward`;
  Aeron directories in `/dev/shm`; operator dictionaries in `/etc/radiusward/dictionary.d`; configuration
  files mounted under `/etc/radiusward`.
- The entrypoint (`deploy/docker/entrypoint.sh`) sets the heap per component and `RADIUSWARD_PROFILE`
  (ADR 0004: node small 384m, gateway small 192m), `-XX:+ExitOnOutOfMemoryError`, G1, and container defaults
  for the data, Aeron and dictionary directories and the management bind address (`0.0.0.0`). Every default is
  an environment variable, so properties files and `JAVA_OPTS` still win.
- **Health checks** use `radiusward probe <url>` (the JRE image has no curl): `/ready` for compose
  `healthcheck` and Kubernetes readiness, `/health` for liveness.
- **Addresses, not names**, in `cluster.members` and `gateway.egress.host` wherever a member can disappear:
  Aeron re-resolves the endpoint of a dead member, and resolving a stopped container's name blocks the media
  driver for seconds (measured in compose: 5.4 s elections with names, 0.6 s with static IPs).
- Published by `release.yml` for `linux/amd64` and `linux/arm64` with SBOM and provenance:
  `:edge` from `main`, `:X.Y.Z` (+ `:X.Y`, `:latest` for final releases) from tags (docs/operations/release.md).

## Consequences
- Image ~100 MB compressed (~340 MB unpacked, mostly the JRE).
- `/dev/shm` must be sized (`shm_size` in compose, `emptyDir: Memory` in Kubernetes): small node 512 MiB,
  gateway 128 MiB.
- On macOS, Docker rewrites the source address of UDP sent through published ports, so a NAS simulator on
  the host does not match a NAS entry; test clients run inside the network (docs/operations/docker.md).
- Fault-injection tests use a separate test image on top of this one (ADR 0016); it is never published.
