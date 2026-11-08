# Phase 2 plan: containers, Linux durability, production defaults

Status: **draft** — scope items collected; the detailed step-by-step plan is written before Phase 2 starts.
Builds on: [Phase 1](phase-1.md)

## Scope (from the roadmap and the Phase 1 report)

- One container image from `radiusward.jar` (entrypoints `cluster-node`, `gateway`, `cluster-tool`),
  docker-compose for the 3 + 2 setup; release images built on Java 25 and pushed to GHCR
  (`ghcr.io/radiusward/radiusward-server`).
- Linux tests for what macOS cannot prove: real fsync / power loss of one node, quorum loss by network
  partition, disk full / fsync failure, sustained overload with `--memory=1g`.
- Memory profiles as compose files; latency profiling on Linux.
- Replace the synthetic vendor fixtures with anonymised captures.
- **Faster failover and production timeouts** (below).

## Faster failover (decided 2026-11-08)

### Measured in Phase 1

`kill -9` of the leader at ~2k req/s (local processes, M4 Pro):

| Step | Time |
|---|---|
| detection (leader heartbeat timeout, configured 3 s) | 3.0 s |
| election | 1.1 s |
| gateways redirected to the new leader | 0.1 s |
| **cluster writable again** | **≈ 4.2 s** |

Clients saw p99 ≈ 6.0 s: a request sent just after the kill is lost with the dead leader, the NAS-like
client retransmits after 3 s (cluster not back yet) and again after 6 s (succeeds). With Aeron's default
10 s heartbeat timeout a failover would take ~11–12 s, ~12–15 s as seen by a NAS — too close to typical NAS
give-up times (3–5 s × 3 attempts).

### Changes

| # | Change | Expected effect |
|---|---|---|
| 1 | Default `cluster.leader.heartbeat.timeout` **1.5 s** for dedicated hosts / compose; **2.5 s** in the Kubernetes Helm values (noisy neighbours). Stays configurable. Heartbeat interval stays at Aeron's 200 ms default (5–7 missed heartbeats before an election) | detection 3 s → 1.5 s |
| 2 | Election timeout **0.5 s** (new key `cluster.election.timeout`, maps to Aeron's `electionTimeoutNs`) | election 1.1 s → ~0.5–0.6 s |
| 3 | Gateway **resubmits all pending requests when it sees a new leader** (`EgressListener.onNewLeader`) instead of waiting for NAS retransmissions; resubmit-on-retransmit (ADR 0011) stays as the fallback. Each pending slot keeps its encoded command (~1 KiB slots, ~16 MiB per gateway in the small profile; larger commands fall back to NAS retransmission) | removes up to one NAS retry interval (3–5 s) from the outage |
| 4 | e2e assertion: during a leader `kill -9` under load, **no request needs more than one attempt** with a 3 s client timeout (the failover finishes below the NAS timeout) | guards the target |

**Target:** cluster writable again in ~2–2.5 s after a leader crash, below a typical 3 s NAS timeout — the NAS
sees one slower answer and never retransmits.

Risks to test: false elections from GC pauses, slow disks or network jitter at the shorter timeouts (run the
overload and fsync tests with the new defaults; measure on Linux and in compose), and the gateway's memory
for stored commands. ADR 0011 gets an amendment, and ADR 0004 the new slot size.
