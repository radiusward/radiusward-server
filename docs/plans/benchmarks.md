# Plan: benchmarks and published benchmark reports

Status: **in progress** (2026-11-11): B1, B2 and B3 done; B4 (AWS) needs an account. ADR [0066](../adr/0066-benchmarks.md). Builds on the test reports
([test-reports.md](test-reports.md)) and Phase 4 ([phase-4.md](phase-4.md)).

## Goal

Know and show how much radiusward carries: the **ceiling** of accounting and of authentication per profile and
machine, how latency and resources behave on the way there, what a failover costs at high load, and whether a change
made it slower. The numbers are collected the same way everywhere, kept with their environment, and published as
pages next to the test reports.

## Decisions (2026-11-11)

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | What is measured | a **ladder**: rising request rates (default 500 → 1k → 2k → 4k → 8k → 16k/s, 60 s per step) of accounting, authentication (PAP, CHAP, MS-CHAPv2) and a mix, until p99 > 500 ms, a request is lost, or less than 90 % of the target rate arrives; the last good step is the ceiling | a ceiling with a precise, repeatable definition |
| 2 | Recorded per step | throughput and p50/p99/max latency, losses and retransmissions (radclient); CPU and memory of every container (`docker stats`), heap, direct memory and GC time (`/metrics`), log position; plus the generators' own CPU, so a saturated generator is not taken for a saturated server | numbers that explain themselves |
| 3 | Failover under load | one leader kill at 70 % of the accounting ceiling, measuring losses, retransmissions and the latency gap | the price of the property radiusward exists for |
| 4 | Micro-benchmarks | the JMH suite (`-Pbench`) with JSON output, run alongside | code-level regressions without a cluster |
| 5 | Output | one JSON file per run: environment (where, machine, CPUs, memory, profile, Java, commit, date), the ladder, the failover, JMH | comparable across places and time |
| 6 | Where | **GitHub runner weekly** (trend: comparable run to run, absolute numbers low), **any machine by hand** (`scripts/bench.py`), **AWS** (the real ceiling per profile, B4) | each answers a different question |
| 7 | Generators | `radclient load` in containers on the stack's network, several in parallel, each with its own sessions | the same on a laptop, a runner and AWS |
| 8 | Pages | a Benchmarks section on the test reports' site, its history inside the site's state like the reports (no commits) | one site, no bot commits |

## Work packages

| # | Package | Content | Size |
|---|---|---|---|
| B1 ✅ | Harness | `scripts/bench.py`: compose stack (or an existing one), ladder for accounting / auth / mix, resource sampling, failover run, JMH, one JSON result; documented in `docs/testing/benchmarks.md` | M |
| B2 ✅ | Weekly run | `bench.yml`: weekly and on demand on a GitHub runner, the result as an artifact `results-bench` | S |
| B3 ✅ | Pages | Benchmarks section in `reports.yml`/`test-reports.sh`: ceiling per environment and profile, throughput–latency charts per ladder, the weekly trend with commits, JMH over time, README badge | M |
| B4 | AWS | the harness against the CloudFormation stack (Graviton, small and standard) with generators on c7g.xlarge; results into the pages and the ECS guide | M (needs an AWS account) |

## Limits

- On one machine (a laptop, a runner) members, gateways and generators share the CPUs: the result is a **lower
  bound** and a trend, not the ceiling; the JSON says so (`environment.shared_host: true`).
- EAP methods are not in the ladder yet: `radclient` has no EAP client; EAP throughput is bounded by TLS handshakes
  and measured with `eapol_test` in a later step.
