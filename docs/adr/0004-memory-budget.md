# ADR 0004: 1 GiB default memory profile

Status: Accepted (2026-11-07). Amended in Phase 2 with measurements.

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
- Measured in Phase 2 (`OverloadIT`: containers limited to 1 GiB / 384 MiB, 2M sessions, 48k requests/s
  offered for 2 min, ~32k/s served): members at most **448 MiB** heap + native + `/dev/shm` (the rest of the
  1 GiB is page cache, reclaimable), gateways at most **321 MiB** of 384 MiB; no OOM kill. The small profile
  holds its 2M-session maximum within 1 GiB.
- The gateway has the least headroom (~16 % at 384 MiB): response cache (~340k entries at that rate) and
  1 KiB per pending slot for stored commands (ADR 0011).
- Profiles appear as Helm values and compose files.
