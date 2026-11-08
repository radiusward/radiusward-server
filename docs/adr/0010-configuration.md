# ADR 0010: Configuration — properties files with environment overrides

Status: Accepted (2026-11-08)

## Context
Every component needs a handful of settings; Kubernetes and Docker prefer environment variables; secrets
must not sit in files; we keep dependencies minimal.

## Decision
- Java `.properties` files, one or more per process (`--config a.properties --config b.properties`), later
  files override earlier ones.
- Any key can be overridden by an environment variable: `cluster.node.id` → `RADIUSWARD_CLUSTER_NODE_ID`
  (upper case, non-alphanumerics become `_`). The environment wins over files.
- Values may reference environment variables, `${env:NAS_SECRET}` or `${env:NAS_SECRET:-default}`, so
  shared secrets come from Kubernetes Secrets or the environment.
- Typed accessors (integer, duration `10s`, size `4m`, boolean, list, enum) fail at startup with the key and
  the expected type. No library (implemented in `common/config/Config`).

## Consequences
- Same mechanism locally, in compose and in Kubernetes. Every key and default is documented in
  [configuration.md](../configuration.md).
- No hierarchical config or hot reload; changes need a restart (NAS changes will become replicated
  commands in a later phase).
