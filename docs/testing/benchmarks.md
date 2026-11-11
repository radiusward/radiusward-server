# Benchmarks

How much radiusward carries, measured the same way everywhere ([ADR 0066](../adr/0066-benchmarks.md),
[plan](../plans/benchmarks.md)).

```bash
scripts/bench.py                      # the full ladder against a fresh compose stack, then failover, one JSON file
scripts/bench.py --quick              # 20 s steps up to 4000/s, no failover: a first look
scripts/bench.py --jmh                # also the JMH micro-benchmarks (testing/benchmarks)
scripts/bench.py --external --workloads accounting --steps 1000,2000   # against a stack that already runs
```

The image is `radiusward:dev` (`--image` for another). Results land in `testing/benchmarks/target/bench/`.

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
retransmission (longest wait 2.2 s). Higher steps follow in the published results.
