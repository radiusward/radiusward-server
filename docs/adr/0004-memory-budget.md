# ADR 0004: 1 GiB default memory profile

Status: Accepted (2026-11-07)

## Context
The product should run in small containers. Aeron and JVM defaults (64 MB term buffers, unbounded
metaspace, 25 % heap) easily exceed 1 GiB per node.

## Decision
Ship profiles, default **small**:

| | small (default) | standard | large |
|---|---|---|---|
| cluster node limit | 1 GiB | 2 GiB | 4 GiB+ |
| heap | ~384 MB | ~1 GB | ~2.5 GB |
| Aeron term length | 1–4 MB | 8 MB | 16–64 MB |
| media driver threading | SHARED | SHARED_NETWORK | DEDICATED |
| idle strategy | backoff / sleeping | backoff | busy-spin |
| gateway limit | 256–384 MiB | 512 MiB | 1 GiB |

Budget for a small node: Aeron buffers in `/dev/shm` ~64–100 MB, heap ~384 MB, metaspace + code cache
~100 MB, threads/native ~50 MB, page-cache headroom ~150 MB. Rules: zero allocation in steady state,
primitive collections, streamed snapshots, explicit JVM flags (`-Xmx`, `MaxMetaspaceSize`,
`ReservedCodeCacheSize`, `MaxDirectMemorySize`), G1.

## Consequences
- Small profile handles ~1–2M concurrent sessions per node; the reference load (500k) uses ~40 MB of
  session state.
- CI will run the 3-node cluster with `--memory=1g` under load and snapshot (Phase 2).
- Profiles appear as Helm values and compose files.
