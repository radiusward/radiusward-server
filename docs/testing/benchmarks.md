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
| `--steps` | `500,1000,2000,4000,8000,16000` | target request rates per second |
| `--duration` | `60` | seconds per step |
| `--generators` | `4` | radclient containers per step |
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

## What it measures

- **Ladders** for `accounting` (Start and Interim records of fresh sessions through both gateways), `access`
  (Access-Requests with PAP, CHAP and MS-CHAPv2, all correct: rejects are held back `auth.reject.delay` on purpose and
  would set the p99) and `mix` (70 % accounting, 30 % authentication). Each step runs `--generators` radclient
  containers on the stack's network for `--duration` seconds at a share of the target rate.
- A step **fails** when an accounting request is lost, an Access-Request times out or is answered wrongly, the p99
  latency passes `--p99-limit` (500 ms), or less than 90 % of the target rate arrives. The ladder stops there; the
  last good step is the **ceiling**.
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
| AWS | the ECS stack with generators on their own instances (planned) | the ceiling per profile |

On a MacBook (Colima, 8 vCPU) the first runs carried accounting at 1,000/s (p99 61 ms), authentication at 2,000/s
(p99 29 ms) and the mix at 2,000/s with every step passing; a leader kill at 700/s lost nothing and caused no
retransmission (longest wait 2.2 s).

The first run on a GitHub runner (4 vCPU shared by members, gateways and generators; the members and gateways kept
the CPUs saturated) carried accounting at **3,788/s** (p99 265 ms), authentication at **3,701/s** and the mix at **1,929/s**; a leader
killed at 2,651/s lost nothing (239 retransmissions, longest wait 3.4 s). JMH: the full receive path at 0.93
operations/µs, about 930k packets per second per core. Every later run is on the
[published pages](https://radiusward.github.io/radiusward-server/benchmarks/).

## Published results

After every `bench` run on `main`, `reports.yml` publishes the
[Benchmarks pages](https://radiusward.github.io/radiusward-server/benchmarks/) next to the test reports: per
environment the ceilings and the failover of its latest run, each ladder as two charts (target against achieved rate,
p99 against the 500 ms limit), CPU and memory per container at the top step, the JMH scores, and the trend of the
ceilings and of JMH over all runs. The runs are kept inside the site's state (`benchmarks/runs/`), like the reports'
history; the landing page has a card and the README a badge (`badges/bench.json`). A result made elsewhere is
published by attaching it to a run as `results-bench` and running `reports.yml` by hand with that run's id; without
one it publishes the latest successful `bench` run. Locally:

```bash
python3 scripts/bench-pages.py testing/benchmarks/target/bench site    # → site/benchmarks/index.html
```
