# ADR 0066: Benchmarks with one harness everywhere

Status: Accepted (2026-11-11). Plan: [plans/benchmarks.md](../plans/benchmarks.md).

## Context
Phase 4 proved that nothing is lost under load, chaos and failover, but its load generators ran out at about 1,760
requests/s on a laptop: radiusward's ceiling is unknown, and nothing tells whether a change made it slower. JMH
micro-benchmarks exist (`-Pbench`) but run only by hand.

## Decision
- **One harness**, `scripts/bench.py`, measures a ladder of rising request rates for accounting, authentication and a
  mix until p99 latency passes 500 ms, a request is lost, or the target rate is no longer answered, then bisects to
  within 10 %; the highest rate that passed is the ceiling. A step that only misses its rate while latency stays
  fine is retried with more generators and otherwise reported as a lower bound ("≥", `load_limited`), so a limit of
  the load generators is never read as one of radiusward. It records latency, losses, retransmissions and every container's CPU and memory per step, adds a
  leader kill at 70 % of the ceiling and the JMH suite, and writes one JSON file with the environment it ran in.
- It runs **weekly on a GitHub runner** for the trend, **by hand anywhere**, and **on AWS** for the real ceiling per
  profile. Results on one machine are marked as a lower bound (`shared_host`).
- Results are published as a Benchmarks section of the test reports' site, kept in its state like the reports.

## Consequences
- The README and the docs can quote measured ceilings with their environment instead of estimates.
- A weekly number on shared runners is noisy; the pages show the trend with its spread, and alarms are not raised on
  single runs.
