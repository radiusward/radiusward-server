# Plan: benchmarks and published benchmark reports

Status: **in progress** (2026-11-11): B1, B2 and B3 done, the ladder refined after the first GitHub run
([findings](#findings-from-the-first-github-run)); B4 (AWS) is planned [below](#b4-aws) and needs an account. ADR [0066](../adr/0066-benchmarks.md). Builds on the test reports
([test-reports.md](test-reports.md)) and Phase 4 ([phase-4.md](phase-4.md)).

## Goal

Know and show how much radiusward carries: the **ceiling** of accounting and of authentication per profile and
machine, how latency and resources behave on the way there, what a failover costs at high load, and whether a change
made it slower. The numbers are collected the same way everywhere, kept with their environment, and published as
pages next to the test reports.

## Decisions (2026-11-11)

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | What is measured | a **ladder**: rising request rates (default 500 → 1k → 2k → 4k → 8k → 16k/s, 60 s per step) of accounting, authentication (PAP, CHAP, MS-CHAPv2) and a mix, until p99 > 500 ms, a request is lost, or less than 90 % of the target rate is answered; then a bisection to within 10 %; the highest rate that passed is the ceiling. A step short only of its rate, with latency fine, is retried with more generators and otherwise reported as a lower bound (`load_limited`, "≥") | a ceiling with a precise, repeatable definition that never takes a generator limit for radiusward's |
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
| B4 | AWS | the harness against the CloudFormation stack (Graviton, small and standard) with generators on their own instances; results into the pages and the ECS guide — [plan below](#b4-aws) | M (needs an AWS account) |

## Findings from the first GitHub run

Run 43045796811 (2026-11-11, 4 vCPU shared by three members, two gateways and four generators) reported accounting
3,788/s, authentication 3,701/s and the mix 1,929/s. The raw steps showed that these were not three ceilings:

- **The ladder was too coarse.** Accounting and authentication both passed 4,000/s and both failed at 8,000/s; the
  "ceiling" was what the 4,000 step delivered. The mix stopped at its 2,000 step for the same reason.
- **Authentication was not limited by radiusward.** At 8,000/s its p99 stayed at 46 ms, as at 500/s, with no
  timeouts; it failed only because 6,915/s arrived. Members, gateways and generators used about 330 % of the 400 %
  CPU: the host and the generators ran out first.
- **Accounting did saturate** at 8,000/s (7,188/s answered, p99 704 ms, nothing lost), but on CPUs shared with the
  generators — a lower bound, as the pages say.
- **The generator lost sends after stalls.** `radclient load` dropped its backlog after falling 10 send gaps behind
  (5 ms at 2,000/s per generator), so every short stall on a busy host lowered the delivered rate: even the 4,000
  step reached only 94 %. It scanned all in-flight slots for timeouts on every loop pass as well.

Fixed in `cea5e67`: the bisection, the load-limited verdict with more generators, the achieved rate counted from
answers, a 100 ms catch-up window and a 10 ms timeout scan in `radclient load`; the pages show "≥" for a lower bound
and every probe. What remains is the machine itself: **only separate machines for the generators give a real
ceiling**, which is what B4 is for.

## B4: AWS

**Goal:** the ceiling of accounting, authentication and the mix for the `small` and `standard` profiles on the
Graviton ECS stack ([aws-ecs.md](../operations/aws-ecs.md)), with the generators on their own instances so the
result is not load-limited, plus the cost of a leader kill there.

**Topology**

- The CloudFormation stack as documented: three members on EC2 (`small` c7g.large, `standard` m7g.large), one per
  availability zone; two gateways on Fargate behind one internal NLB each; the backup on Fargate with EFS.
- **Generators**: c7g.xlarge instances (4 vCPU) in the same VPC, running the `radclient load` container from the same
  image, aimed at both NLBs. Start with two instances × 4 generators, in two zones; the load-limited verdict adds
  generators, and a third or fourth instance is added when one instance's CPU passes 70 %. Their addresses fall
  inside `NasCidr`.
- Generators reach the members' and gateways' `/metrics` on port 9090 (already open to the VPC).

**Harness changes** (B4a, without AWS access)

- `bench.py --target <nlb-a>,<nlb-b> --generator-hosts <h1>,<h2>`: no compose stack; generators started on the
  instances (`docker run` over SSM or SSH), results gathered from their output as today; `shared_host: false`.
- CPU per process from `/metrics` instead of `docker stats`: add `radiusward_process_cpu_seconds_total` (JVM
  `OperatingSystemMXBean`) to members, gateways and the backup — useful for every deployment, not only here; the
  generators' CPU from the instances.
- Failover: find the leader from `/state`, then `aws ecs stop-task` on its task; ECS starts a replacement, which seeds
  itself (ADR 0063) — the run measures losses and the gap as on GitHub.
- `environment`: region, instance types and task sizes, profile, image digest.

**Runbook** (B4b): `scripts/bench-aws.sh <profile>` deploys the stack and a small generator stack
(`deploy/aws/bench/generators.yaml`, test only), waits for `/ready`, runs the ladder (60 s steps from 1,000/s, 10 %
resolution), the failover and nothing else, collects the JSON and **deletes both stacks on exit, also after a
failure**. One run per profile; about 45 minutes each plus 15 for the stacks.

**Credentials and publishing**: a first run from a workstation with an IAM Identity Center profile
(`aws sso login`, short-lived credentials, never access keys). After that, `bench-aws.yml` on demand in GitHub
Actions with an **OIDC role** (no stored secret; the role allowed only for this repository's `main` and limited to
the stacks' resources), so the result becomes a `results-bench` artifact and the pages publish it as the
environments `aws-small` and `aws-standard`.

**Cost**: members, Fargate tasks, two NLBs, EFS and two generator instances for about 3 hours for both profiles —
a few dollars, under $15 with data transfer between zones. A budget alert on the account is recommended.

**Done when**: both profiles have ceilings that are not load-limited, the leader kill lost nothing, the results are
on the pages, and the sizing table of the ECS guide quotes them.

**Needs from the maintainer**: an AWS account with an Identity Center user and a permission set for ECS, EC2, ELB,
EFS, CloudFormation, Cloud Map, Secrets Manager, S3 and roles named `radiusward-*`; a region; for the workflow, the
OIDC role (a template comes with B4b).

| # | Step | Needs AWS |
|---|---|---|
| B4a | `bench.py` remote mode, process CPU metric, ECS failover | no |
| B4b | `bench-aws.sh`, generator stack, OIDC role template, `bench-aws.yml` | no (validated with cfn-lint) |
| B4c | first run per profile from a workstation, results on the pages and in the ECS guide | yes |
| B4d | on demand in GitHub Actions | yes (OIDC role) |

## Limits

- On one machine (a laptop, a runner) members, gateways and generators share the CPUs: the result is a **lower
  bound** and a trend, not the ceiling; the JSON says so (`environment.shared_host: true`), and a ladder that ran
  out of load says so too (`load_limited`).
- EAP methods are not in the ladder yet: `radclient` has no EAP client; EAP throughput is bounded by TLS handshakes
  and measured with `eapol_test` in a later step.
