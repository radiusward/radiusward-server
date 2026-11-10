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
| heap | ~256 MB | ~768 MB | ~2 GB |
| direct memory (session state, ADR 0012) | 576 MB | 1.5 GB | 5 GB |
| Aeron term length | 1–4 MB | 8 MB | 16–64 MB |
| media driver threading | SHARED | SHARED_NETWORK | DEDICATED |
| idle strategy | backoff / sleeping | backoff | busy-spin |
| gateway limit | 256–384 MiB | 512 MiB | 1 GiB |

Budget for a small node: Aeron buffers in `/dev/shm` ~64–100 MB, heap ~256 MB, session state off-heap up to
~460 MB at 2M sessions (member and replica, ADR 0012, 0036), metaspace + code cache
~100 MB, threads/native ~50 MB, page-cache headroom ~150 MB. Rules: zero allocation in steady state,
primitive collections, streamed snapshots, explicit JVM flags (`-Xmx`, `MaxMetaspaceSize`,
`ReservedCodeCacheSize`, `MaxDirectMemorySize`), G1.

## Consequences
- Small profile handles ~1–2M concurrent sessions per node; the reference load (500k) uses ~40 MB of
  session state (~48 MB since state version 6 keeps each session's user and device for simultaneous use,
  ADR 0023: +16 bytes per session, ~+32 MB at 2M sessions). State version 7 keeps each session's identifying
  attributes for CoA (ADR 0036). Since then the whole store is off-heap: ~168 bytes per session on a member, ~72 in
  the exporter's replica; heap and direct memory are set per profile (standard and large estimated, not measured).
- Measured again 2026-11-10 (`OverloadIT`, state version 7 active, 2M sessions with identities): members at most
  688 / 630 / **883 MiB** unreclaimable of 1 GiB (the highest is the exporter's lease owner: replica and PostgreSQL
  batches), gateways at most 320 MiB of 384 MiB; no OOM kill. `StateFootprintIT` guards the state's share (heap
  < 128 MiB, direct < 512 MiB at 2M) in seconds.
- Measured in Phase 2 (`OverloadIT`: containers limited to 1 GiB / 384 MiB, 2M sessions, 48k requests/s
  offered for 2 min, ~32k/s served): members at most **448 MiB** heap + native + `/dev/shm` (the rest of the
  1 GiB is page cache, reclaimable), gateways at most **321 MiB** of 384 MiB; no OOM kill. The small profile
  holds its 2M-session maximum within 1 GiB.
- The gateway has the least headroom (~16 % at 384 MiB): response cache (~340k entries at that rate) and
  1 KiB per pending slot for stored commands (ADR 0011).
- Profiles appear as Helm values and compose files.
