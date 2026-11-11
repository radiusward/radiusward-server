# Benchmarks

How much radiusward carries, measured the same way everywhere ([ADR 0066](../adr/0066-benchmarks.md),
[plan](../plans/benchmarks.md)).

```bash
scripts/bench.py                      # the full ladder against a fresh compose stack, then failover, one JSON file
scripts/bench.py --quick              # 20 s steps up to 4000/s, no failover: a first look
scripts/bench.py --jmh                # also the JMH micro-benchmarks (testing/benchmarks)
scripts/bench.py --external --workloads accounting --steps 1000,2000   # against a stack that already runs
```

The image is `radiusward:dev` (`--image` or `RADIUSWARD_IMAGE` for another). Results land in
`testing/benchmarks/target/bench/` (`--out`).

| Option | Default | |
|---|---|---|
| `--steps` | `500,1000,2000,4000,8000,16000,32000` | target request rates per second |
| `--duration` | `60` | seconds per step |
| `--generators` | `4` | radclient containers per step |
| `--max-generators` | `8` | a step short of its rate with latency fine is repeated with up to this many |
| `--resolution` | `0.1` | bisect between the last good and the failed step down to this share of the rate |
| `--workloads` | `accounting,access,mix` | which ladders |
| `--p99-limit` | `500` | ms; above it a step fails |
| `--interim` | `10` | interim interval of the accounting sessions, seconds |
| `--pause` | `10` | seconds between steps |
| `--where` | `local` (`BENCH_WHERE`) | the environment's label in the result and on the pages |
| `--external` | | use the running compose stack and leave it running |
| `--monitoring` | | also start Prometheus and Grafana, to watch a run |
| `--no-failover` | | skip the leader kill |
| `--jmh` | | also run the JMH suite |
| `--quick` | | 20 s steps, 250 → 4000/s, no failover |
| `--secret` | `testing123` | the NAS entry's shared secret |
| `--target` | | gateway addresses of a remote stack (the ECS load balancers); no compose stack |
| `--ecs-cluster` | | with `--target`: the ECS cluster, to find the tasks' metrics and stop the leader's task |
| `--generator-hosts` | `local` | where the generators run, round robin: `local` or EC2 instance ids (started through SSM) |
| `--label` | | `key=value` recorded in the result's environment (region, instance types) |

Against a remote stack the CPU per process comes from `radiusward_process_cpu_seconds_total` on each `/metrics`
(cores in use over the step) instead of `docker stats`, and the failover stops the leader's ECS task; ECS replaces it
and the harness waits until every member is ready again.

## What it measures

- **Ladders** for `accounting` (Start and Interim records of fresh sessions through both gateways), `access`
  (Access-Requests with PAP, CHAP and MS-CHAPv2, all correct: rejects are held back `auth.reject.delay` on purpose and
  would set the p99) and `mix` (70 % accounting, 30 % authentication). Each step runs `--generators` radclient
  containers on the stack's network for `--duration` seconds at a share of the target rate.
- A step **fails** when an accounting request is lost, an Access-Request times out or is answered wrongly, the p99
  latency passes `--p99-limit` (500 ms), or less than 90 % of the target rate is answered (the achieved rate counts
  answers over the step's length, not requests sent).
- After the first failed step the harness **bisects** between the last good and the failed rate until they are
  `--resolution` (10 %) apart; the highest rate that passed is the **ceiling**.
- A step that only misses its rate while nothing was lost and p99 stayed within the limit was held back by the load
  generators or the host, not by radiusward: it runs again with twice the generators (up to `--max-generators`).
  If it still misses, the ladder stops and the ceiling is a **lower bound**, shown as "≥" and marked `load_limited`.
- `radclient load` catches up after a stall of up to 100 ms (a GC pause, a busy host) by sending faster for a moment,
  so short stalls do not lower the delivered rate.
- Per step: throughput, p50/p99/max latency, retransmissions, every container's average and peak CPU and peak memory
  (`docker stats`, generators included, so a saturated generator shows), and the members' heap, direct memory, GC
  time, sessions and log position (`/metrics`).
- **Failover**: accounting at 70 % of its ceiling for 90 s with the leader killed after 30 s; losses fail it, the
  gap shows as the maximum latency.
- **JMH** (`--jmh`): the codec and hot-path micro-benchmarks, as scores with their error.

## Where it runs

| Where | How | Read the numbers as |
|---|---|---|
| any machine | `scripts/bench.py` | a lower bound: members, gateways and generators share the CPUs (`environment.shared_host`) |
| GitHub runner | `bench.yml`, Sundays and on demand; artifact `results-bench` | a weekly trend on a 4-vCPU runner |
| AWS | `scripts/bench-aws.sh` or `bench-aws.yml` on demand: the ECS stack with generators on their own instances ([below](#on-amazon-ecs)) | the ceiling per profile |

On a MacBook (Colima, 8 vCPU) the first runs carried accounting at 1,000/s (p99 61 ms), authentication at 2,000/s
(p99 29 ms) and the mix at 2,000/s with every step passing; a leader kill at 700/s lost nothing and caused no
retransmission (longest wait 2.2 s).

On a GitHub runner (4 vCPU shared by three members, two gateways, PostgreSQL and the generators), the run of
2026-11-11 with the refined ladder carried:

| Workload | Ceiling | Stopped by | CPU at the ceiling |
|---|---|---|---|
| accounting | **3,731/s** | p99 609 ms at 4,000/s | members 0.5–0.7 cores each, gateways 0.6 each: the runner's 4 cores busy |
| authentication | **≥ 15,053/s** | nothing: every step up to 16,000/s passed, p99 200 ms | gateways 0.7 each, members 0.2 |
| mix (70/30) | **6,821/s** | p99 708 ms at 7,500/s | |

A leader killed at 2,611/s lost nothing and caused no retransmission (longest wait 2.5 s). JMH: the full receive
path at 1.3 operations/µs, about 1.3 million packets per second on one core. Accounting is bounded by replication
and fsync on three members sharing four cores; authentication runs on the gateways and stays far from its limit. The
numbers of one shared runner vary from run to run (the mix carried more accounting than the accounting ladder
alone), so the pages show the trend. The first run, before the ladder was refined, reported 3,788 / 3,701 /
1,929 per second: its authentication and mix figures were limits of the coarse steps and the load generators
([findings](../plans/benchmarks.md#findings-from-the-first-github-run)). Every run is on the
[published pages](https://radiusward.github.io/radiusward-server/benchmarks/).

## On Amazon ECS

`scripts/bench-aws.sh` runs the same harness against the ECS stack ([aws-ecs.md](../operations/aws-ecs.md)) with the
load generators on their own Graviton instances, so the result is radiusward's ceiling on that profile, not a
shared machine's:

```bash
aws sso login --profile <aws profile>
AWS_PROFILE=<aws profile> scripts/bench-aws.sh --profile small --region eu-central-1   # then --profile standard
```

1. Deploys `deploy/aws/bench/generators.yaml` (test only: a VPC with public and private subnets, one NAT gateway, a
   results bucket, two to four c7g.xlarge generators reachable only through SSM) and the radiusward stack in its
   private subnets with internal load balancers.
2. Configures the gateways for the benchmark: a fresh NAS secret, a NAS entry for the VPC, the `load` user in the
   users file secret, authentication on.
3. Runs `scripts/bench.py` on the first generator through SSM (`--target`, `--ecs-cluster`, `--generator-hosts`):
   generators on every instance, CPU per process from `/metrics`, the failover by stopping the leader's task.
4. Copies the result to `testing/benchmarks/target/bench/` and **deletes both stacks**, also after a failure or
   Ctrl-C (`--keep` leaves them, `--delete-only` removes them later).

It takes about an hour per profile and costs a few dollars. Credentials are short-lived (IAM Identity Center); the
account needs room for about 16 vCPUs of on-demand standard instances. From GitHub Actions, `bench-aws.yml` runs it
on demand with OpenID Connect: deploy `deploy/aws/bench/github-oidc.yaml` once (a role only this repository's
`main` may assume, limited to `radiusward-bench-*` stacks and roles), store its `RoleArn` as the repository variable
`AWS_BENCH_ROLE_ARN` and the region as `AWS_BENCH_REGION`; `reports.yml` publishes the results as `aws-small` and
`aws-standard`.

## Published results

After every `bench` and `bench-aws` run on `main`, `reports.yml` publishes the
[Benchmarks pages](https://radiusward.github.io/radiusward-server/benchmarks/) next to the test reports, written for
readers who do not know the harness: what radiusward is and how a result is measured, then per environment
(dedicated machines first) the result cards — the three ceilings with their p99 and p50, and the leader killed under
load — what ran on the machine, the peak memory, each ladder as two charts with a caption (target against answered
rate, p99 against the 500 ms limit), CPU and memory per process at the ceiling, every step sorted by rate with its run
order, the gateway's packet path from JMH in nanoseconds per packet and packets per second on one core, the trend over
all runs, and links to the other reports and to reproducing the numbers. The summary, the landing card and the badge
show the newest run on dedicated machines once there is one. Claims stay with what was measured: no extrapolation to
other machines, no comparisons with other products. The runs are kept inside the site's state (`benchmarks/runs/`), like the reports'
history; the landing page has a card and the README a badge (`badges/bench.json`). A result made elsewhere is
published by attaching it to a run as `results-bench` and running `reports.yml` by hand with that run's id; without
one it publishes the latest successful `bench` run. Locally:

```bash
python3 scripts/bench-pages.py testing/benchmarks/target/bench site    # → site/benchmarks/index.html
```
