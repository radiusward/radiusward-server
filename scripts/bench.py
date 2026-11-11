#!/usr/bin/env python3
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
"""Benchmark harness (ADR 0066, docs/testing/benchmarks.md).

Starts the compose stack (or uses a running one), climbs a ladder of request rates for accounting, authentication
and a mix with radclient load generators in containers until p99 latency passes the limit, a request is lost or the
target rate no longer arrives, samples every container's CPU and memory, kills the leader at 70 % of the accounting
ceiling, optionally runs the JMH suite, and writes one JSON result.

  scripts/bench.py                          # full ladder on this machine
  scripts/bench.py --quick                  # short steps, for a first look
  scripts/bench.py --steps 1000,2000 --workloads accounting --external   # against a stack that already runs
  scripts/bench.py --target nlb-a,nlb-b --ecs-cluster c --generator-hosts local,i-0abc --secret s --where aws-small
                                            # against the ECS stack, from inside its VPC (scripts/bench-aws.sh)
"""

import shlex

import argparse
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSE_FILE = os.path.join(ROOT, "deploy/compose/compose.yaml")
# the compose plugin (GitHub runners, Docker Desktop) or the standalone docker-compose (e.g. Colima)
COMPOSE = (["docker", "compose"] if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0
           else ["docker-compose"]) + ["-f", COMPOSE_FILE]
NETWORK = "radiusward_radius"
GATEWAYS = ["172.28.0.20", "172.28.0.21"]
MEMBER_PORTS = [9090, 9091, 9092]          # published management ports of node-0..2
GATEWAY_PORTS = [9190, 9191]
STACK = None                               # LocalStack or EcsStack, set by main()
ARGS = None
MAX_PROBES = 19                            # per workload: 20M session ids each within the workload's 400M
LOAD = re.compile(r"^load: sent (\d+), acked (\d+), failed (\d+), retransmissions (\d+) in ([\d.]+)s \(([\d.]+) req/s\);"
                  r" latency p50 ([\d.]+) ms, p99 ([\d.]+) ms, max ([\d.]+) ms")
ACCESS = re.compile(r"^access: sent (\d+) \((\d+) with a wrong password\), accepted (\d+), rejected (\d+), challenged (\d+),"
                    r" timeouts (\d+), unexpected (\d+); latency p50 ([\d.]+) ms, p99 ([\d.]+) ms")


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def compose(*args, profiles=()):
    cmd = list(COMPOSE)
    for p in profiles:
        cmd += ["--profile", p]
    return run(cmd + list(args))


def environment(args, image):
    def cmd(c):
        r = run(c)
        return r.stdout.strip() if r.returncode == 0 else ""
    docker = cmd(["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}} {{.Architecture}} {{.OperatingSystem}}"]).split(" ", 3)
    java = run(["docker", "run", "--rm", "--entrypoint", "java", image, "-version"])
    return {
        "where": args.where,
        "shared_host": not (args.external_generators or STACK.remote),
        "labels": dict(label.split("=", 1) for label in args.label),
        "host": {"system": platform.system(), "machine": platform.machine(), "cpus": os.cpu_count()},
        "docker": {"cpus": int(docker[0]) if docker and docker[0].isdigit() else None,
                   "memory_bytes": int(docker[1]) if len(docker) > 1 and docker[1].isdigit() else None,
                   "arch": docker[2] if len(docker) > 2 else None, "os": docker[3] if len(docker) > 3 else None},
        "image": image,
        "image_revision": cmd(["docker", "image", "inspect", image, "--format",
                               '{{index .Config.Labels "org.opencontainers.image.revision"}}']),
        "commit": cmd(["git", "-C", ROOT, "rev-parse", "HEAD"]) or os.environ.get("GITHUB_SHA", ""),
        "profile": os.environ.get("RADIUSWARD_PROFILE", "small"),
        "java": next((l for l in java.stderr.splitlines() if "version" in l), ""),
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


class Sampler:
    """docker stats every few seconds while a step runs: CPU % and memory per container."""

    def __init__(self, interval=3, enabled=True):
        self.interval, self.samples, self._stop, self.enabled = interval, {}, threading.Event(), enabled
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        while not self._stop.is_set():
            r = run(["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"])
            for line in r.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) != 3 or not parts[0].startswith(("radiusward", "bench-gen")):
                    continue
                cpu = float(parts[1].rstrip("%") or 0)
                mem = parse_size(parts[2].split("/")[0].strip())
                self.samples.setdefault(parts[0], []).append((cpu, mem))
            self._stop.wait(self.interval)

    def __enter__(self):
        if self.enabled:
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self.enabled:
            self._thread.join()

    def summary(self):
        out = {}
        for name, s in sorted(self.samples.items()):
            name = re.sub(r"^radiusward-(.*?)-1$", r"\1", name)
            out[name] = {"cpu_avg_pct": round(statistics.mean(c for c, _ in s), 1),
                         "cpu_max_pct": round(max(c for c, _ in s), 1),
                         "mem_max_bytes": max(m for _, m in s)}
        return out


def parse_size(text):
    m = re.match(r"([\d.]+)\s*([KMGT]?i?B)", text)
    if not m:
        return 0
    unit = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
            "kB": 1000, "KB": 1000, "MB": 10 ** 6, "GB": 10 ** 9}.get(m.group(2), 1)
    return int(float(m.group(1)) * unit)


def scrape(url):
    if not url:
        return {}
    try:
        import urllib.request
        with urllib.request.urlopen(f"{url}/metrics", timeout=5) as r:
            text = r.read().decode()
    except Exception:
        return {}
    values = {}
    for line in text.splitlines():
        for key, pattern in (("heap_used_bytes", r'^radiusward_jvm_memory_used_bytes\{area="heap"\} (\S+)'),
                             ("direct_bytes", r'^radiusward_jvm_buffer_used_bytes\{pool="direct"\} (\S+)'),
                             ("gc_pause_seconds_total", r'^radiusward_jvm_gc_pause_seconds_total\{[^}]*\} (\S+)'),
                             ("log_position_bytes", r'^radiusward_cluster_log_position_bytes\{[^}]*\} (\S+)'),
                             ("sessions_active", r'^radiusward_sessions\{[^}]*state="active"\} (\S+)'),
                             ("cpu_seconds_total", r'^radiusward_process_cpu_seconds_total (\S+)')):
            m = re.match(pattern, line)
            if m:
                values[key] = values.get(key, 0) + float(m.group(1))
    return values


class LocalStack:
    """The compose stack on this machine: generators on its network, metrics on the published ports."""

    remote = False

    def __init__(self, args):
        self.args = args

    def gateways(self):
        return GATEWAYS

    def member_urls(self):
        return [f"http://127.0.0.1:{p}" for p in MEMBER_PORTS]

    def gateway_urls(self):
        return [f"http://127.0.0.1:{p}" for p in GATEWAY_PORTS]

    def kill_member(self, n):
        run(["docker", "kill", f"radiusward-node-{n}-1"])

    def recover(self):
        compose("up", "-d", "--wait", profiles=["monitoring"] if self.args.monitoring else ())


class EcsStack:
    """A stack on Amazon ECS (deploy/aws): the gateways' load balancers from --target, the tasks' addresses from the
    ECS cluster (they change when a task is replaced), a member killed by stopping its task. Runs inside the VPC."""

    remote = True

    def __init__(self, args):
        self.args, self.cluster = args, args.ecs_cluster

    def gateways(self):
        return self.args.target.split(",")

    def _tasks(self, service):
        r = run(["aws", "ecs", "list-tasks", "--cluster", self.cluster, "--service-name", service,
                 "--desired-status", "RUNNING", "--query", "taskArns", "--output", "json"])
        arns = json.loads(r.stdout or "[]") if r.returncode == 0 else []
        if not arns:
            return []
        r = run(["aws", "ecs", "describe-tasks", "--cluster", self.cluster, "--tasks", *arns, "--output", "json"])
        tasks = json.loads(r.stdout)["tasks"] if r.returncode == 0 else []
        out = []
        for t in tasks:
            ip = next((d["value"] for a in t.get("attachments", []) for d in a.get("details", [])
                       if d.get("name") == "privateIPv4Address"), None)
            out.append((t["taskArn"], ip))
        return out

    def _urls(self, prefix, count):
        urls = []
        for n in range(count):
            tasks = self._tasks(f"{prefix}-{n}")
            urls.append(f"http://{tasks[0][1]}:9090" if tasks and tasks[0][1] else None)
        return urls

    def member_urls(self):
        return self._urls("node", 3)

    def gateway_urls(self):
        return self._urls("gateway", 2)

    def kill_member(self, n):
        for arn, _ in self._tasks(f"node-{n}"):
            run(["aws", "ecs", "stop-task", "--cluster", self.cluster, "--task", arn,
                 "--reason", "benchmark: leader killed under load"])

    def recover(self):
        """Waits until every member answers /ready again: ECS replaces the stopped task, which seeds itself."""
        deadline = time.time() + 600
        while time.time() < deadline:
            urls = self.member_urls()
            if all(u and ready(u) for u in urls):
                return
            time.sleep(10)
        log("  not every member is ready again after 10 min")


def ready(url):
    try:
        import urllib.request
        with urllib.request.urlopen(f"{url}/ready", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def ssm_run(instance, command, timeout):
    """Runs a shell command on an EC2 instance through SSM and returns its output (the tail; SSM keeps 24,000
    characters)."""
    r = run(["aws", "ssm", "send-command", "--instance-ids", instance, "--document-name", "AWS-RunShellScript",
             "--parameters", json.dumps({"commands": [command], "executionTimeout": [str(timeout)]}),
             "--query", "Command.CommandId", "--output", "text"])
    if r.returncode != 0:
        return f"ssm send-command failed: {r.stderr.strip()}"
    command_id = r.stdout.strip()
    deadline = time.time() + timeout + 120
    while time.time() < deadline:
        time.sleep(5)
        g = run(["aws", "ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", instance,
                 "--output", "json"])
        if g.returncode != 0:
            continue  # the invocation is not registered yet
        d = json.loads(g.stdout)
        if d["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            return d.get("StandardOutputContent", "") + d.get("StandardErrorContent", "")
    return "ssm: no result in time"


def generators(workload, rate, seconds, count, image, first_session, interim):
    """Starts `count` load containers sharing `rate` requests/s; returns their outputs."""
    per = max(1, rate // count)
    procs = []
    for g in range(count):
        args = ["radclient", "load", "--server", ",".join(f"{gw}:1813" for gw in STACK.gateways()),
                "--retry-other-server", "--secret", ARGS.secret, "--nas", "20", "--duration", f"{seconds}s", "--timeout", "3s",
                "--retries", "3", "--first-session", str(first_session + g * 2_000_000)]
        if workload == "accounting":
            args += ["--sessions", str(per * interim), "--rate", str(per), "--interim", f"{interim}s", "--no-stop"]
        elif workload == "access":
            # no wrong passwords: rejects are held back auth.reject.delay (1 s) on purpose and would set the p99
            args += ["--sessions", "0", "--access-rate", str(per), "--auth-methods", "pap,chap,mschapv2",
                     "--reject-ratio", "0"]
        else:  # mix: 70 % accounting, 30 % authentication
            acct, auth = max(1, per * 7 // 10), max(1, per * 3 // 10)
            args += ["--sessions", str(acct * interim), "--rate", str(acct), "--interim", f"{interim}s", "--no-stop",
                     "--access-rate", str(auth), "--auth-methods", "pap,chap,mschapv2", "--reject-ratio", "0"]
        name = f"bench-gen-{g}"
        host = ARGS.generator_hosts[g % len(ARGS.generator_hosts)] if ARGS.generator_hosts else "local"
        network = "host" if STACK.remote else NETWORK
        docker = ["docker", "run", "--rm", "--name", name, "--network", network, image] + args
        if host == "local":
            run(["docker", "rm", "-f", name])
            procs.append(subprocess.Popen(docker, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
        else:  # an EC2 instance, through SSM
            command = f"docker rm -f {name} >/dev/null 2>&1; {shlex.join(docker)} 2>&1 | tail -n 20"
            procs.append(Remote(host, command, seconds + 180))
    return [p.communicate()[0] for p in procs]


class Remote(threading.Thread):
    """A generator on another instance, with the interface of Popen that generators() uses."""

    def __init__(self, instance, command, timeout):
        super().__init__(daemon=True)
        self.args, self.output = (instance, command, timeout), ""
        self.start()

    def run(self):
        self.output = ssm_run(*self.args)

    def communicate(self):
        self.join()
        return self.output, None


def combine(outputs, target, workload, seconds):
    """The generators' summaries as one step; the achieved rate counts answered requests over the step's length."""
    loads, accesses = [], []
    for out in outputs:
        for line in out.splitlines():
            if (m := LOAD.match(line)):
                loads.append([float(x) for x in m.groups()])
            if (m := ACCESS.match(line)):
                accesses.append([float(x) for x in m.groups()])
    step = {"target_rps": target, "generators": len(outputs)}
    rps = 0.0
    p99s, p50s = [], []
    if loads:
        step["accounting"] = {
            "sent": int(sum(l[0] for l in loads)), "acked": int(sum(l[1] for l in loads)),
            "failed": int(sum(l[2] for l in loads)), "retransmissions": int(sum(l[3] for l in loads)),
            "rps": round(sum(l[1] for l in loads) / seconds, 1),
            "p50_ms": round(statistics.median(l[6] for l in loads), 1), "p99_ms": round(max(l[7] for l in loads), 1),
            "max_ms": round(max(l[8] for l in loads), 1)}
        rps += step["accounting"]["rps"]
        p99s.append(step["accounting"]["p99_ms"])
        p50s.append(step["accounting"]["p50_ms"])
    if accesses:
        sent = int(sum(a[0] for a in accesses))
        answered = int(sum(a[2] + a[3] + a[4] for a in accesses))
        step["access"] = {
            "sent": sent, "accepted": int(sum(a[2] for a in accesses)), "rejected": int(sum(a[3] for a in accesses)),
            "timeouts": int(sum(a[5] for a in accesses)), "unexpected": int(sum(a[6] for a in accesses)),
            "p50_ms": round(statistics.median(a[7] for a in accesses), 1),
            "p99_ms": round(max(a[8] for a in accesses), 1)}
        step["access"]["rps"] = round(answered / seconds, 1)
        rps += step["access"]["rps"]
        p99s.append(step["access"]["p99_ms"])
    step["rps"] = round(rps, 1)
    step["p99_ms"] = max(p99s) if p99s else None
    if not loads and not accesses:
        step["error"] = "no generator summary: " + " | ".join(o.strip().splitlines()[-1] if o.strip() else "" for o in outputs)
    return step


def verdict(step, limit_ms):
    """Why a step failed: (reasons, load_limited). A step that is short of its target rate while nothing was lost and
    p99 stayed within the limit was limited by the load generators or the host, not by radiusward."""
    reasons, server = [], False
    if "error" in step:
        reasons.append(step["error"])
        server = True
    a, x = step.get("accounting", {}), step.get("access", {})
    if a.get("failed"):
        reasons.append(f"{a['failed']} accounting requests lost")
        server = True
    if x.get("timeouts") or x.get("unexpected"):
        reasons.append(f"{x.get('timeouts', 0)} Access-Request timeouts, {x.get('unexpected', 0)} wrong answers")
        server = True
    if step.get("p99_ms") is not None and step["p99_ms"] > limit_ms:
        reasons.append(f"p99 {step['p99_ms']} ms > {limit_ms} ms")
        server = True
    short = step.get("rps") is not None and step["rps"] < 0.9 * step["target_rps"]
    if short:
        reasons.append(f"only {step['rps']} of {step['target_rps']} requests/s arrived")
    return reasons, short and not server


def ladder(workload, steps, args, image, first):
    """Climbs `steps` until one fails, then bisects between the last good and the failed rate down to --resolution.
    A step that only misses its rate while latency is fine is run again with twice the generators (up to
    --max-generators); if it still misses, the ladder stops there and the ceiling is a lower bound (load_limited)."""
    log(f"{workload}: ladder {steps}")
    results = []
    probes = 0

    def probe(rate, count):
        nonlocal probes
        # session ids are 32-bit: workloads 400M apart, probes 20M, generators 2M
        urls = {f"node-{n}": u for n, u in enumerate(STACK.member_urls())}
        urls.update({f"gateway-{n}": u for n, u in enumerate(STACK.gateway_urls())})
        before, started = {name: scrape(u) for name, u in urls.items()}, time.time()
        with Sampler(enabled=not STACK.remote) as sampler:
            outputs = generators(workload, rate, args.duration, count, image, first + probes * 20_000_000,
                                 args.interim)
        probes += 1
        after, elapsed = {name: scrape(u) for name, u in urls.items()}, time.time() - started
        for name, values in after.items():  # cores in use over the step, from the process's own CPU time
            if "cpu_seconds_total" in values and "cpu_seconds_total" in before.get(name, {}):
                values["cpu_cores"] = round(
                    (values["cpu_seconds_total"] - before[name]["cpu_seconds_total"]) / elapsed, 2)
        step = combine(outputs, rate, workload, args.duration)
        step["generators"] = count
        step["containers"] = sampler.summary() or {
            name: {"cpu_avg_pct": v["cpu_cores"] * 100, "cpu_max_pct": v["cpu_cores"] * 100,
                   "mem_max_bytes": int(v.get("heap_used_bytes", 0) + v.get("direct_bytes", 0))}
            for name, v in after.items() if "cpu_cores" in v}
        step["members"] = {n: v for n, v in after.items() if n.startswith("node-")}
        step["gateways"] = {n: v for n, v in after.items() if n.startswith("gateway-")}
        step["problems"], step["load_limited"] = verdict(step, args.p99_limit)
        results.append(step)
        log(f"  {rate:>6}/s ×{count} → {step['rps']:>8}/s, p99 {step['p99_ms']} ms"
            + ((f"  ✗ {'; '.join(step['problems'])}" + (" (load-limited)" if step["load_limited"] else ""))
               if step["problems"] else "  ✓"))
        time.sleep(args.pause)
        return step

    count = args.generators

    def step_at(rate):
        nonlocal count  # once more generators were needed, the higher rates keep them
        step = probe(rate, count)
        while step["load_limited"] and count * 2 <= args.max_generators and probes < MAX_PROBES:
            count *= 2
            log(f"  short of the rate with latency fine: again with {count} generators")
            step = probe(rate, count)
        return step

    good, failed = None, None
    for rate in steps:
        if probes >= MAX_PROBES:
            break
        step = step_at(rate)
        if step["problems"]:
            failed = step
            break
        good = step
    if failed is not None and not failed["load_limited"]:
        low = good["target_rps"] if good else 0
        high = failed["target_rps"]
        while low and high - low > max(args.resolution * low, 100) and probes < MAX_PROBES:
            mid = int(round((low + high) / 2 / 50) * 50)
            step = step_at(mid)
            if step["problems"]:
                failed = step
                high = mid
                if step["load_limited"]:
                    break
            else:
                good = step
                low = mid
    passed = [r["rps"] for r in results if not r["problems"]]
    load_limited = failed is not None and failed["load_limited"]
    if load_limited:
        passed.append(failed["rps"])  # nothing lost, latency fine: radiusward carried what arrived
    return {"steps": results, "ceiling_rps": max(passed, default=0), "load_limited": load_limited,
            "stopped_by": "; ".join(failed["problems"]) if failed else None}


def leader():
    for n, url in enumerate(STACK.member_urls()):
        if not url:
            continue
        try:
            import urllib.request
            with urllib.request.urlopen(f"{url}/ready", timeout=3) as r:
                if '"LEADER' in r.read().decode():
                    return n
        except Exception:
            continue
    return None


def failover(ceiling, args, image):
    rate = int(ceiling * 0.7)
    if rate < 50:
        return {"skipped": "no accounting ceiling"}
    log(f"failover: {rate}/s of accounting, the leader killed after 30 s")
    victim = {}

    def kill():
        time.sleep(30)
        n = leader()
        victim["member"] = n
        if n is not None:
            STACK.kill_member(n)
            log(f"  killed member {n}")

    killer = threading.Thread(target=kill)
    killer.start()
    with Sampler(enabled=not STACK.remote):
        outputs = generators("accounting", rate, max(90, args.duration), args.generators, image, 2_000_000_000,
                             args.interim)
    killer.join()
    step = combine(outputs, rate, "accounting", max(90, args.duration))
    step["killed_member"] = victim.get("member")
    step["problems"] = verdict(step, 10_000)[0]  # a failover is allowed its gap; losses are not
    log(f"  {step['rps']}/s, max {step.get('accounting', {}).get('max_ms')} ms, "
        f"{step.get('accounting', {}).get('retransmissions')} retransmissions"
        + (f"  ✗ {'; '.join(step['problems'])}" if step["problems"] else "  ✓ nothing lost"))
    STACK.recover()
    return step


def jmh(args):
    jar = os.path.join(ROOT, "testing/benchmarks/target/benchmarks.jar")
    if not os.path.exists(jar):
        log("jmh: building testing/benchmarks")
        r = run([os.path.join(ROOT, "mvnw"), "-B", "-q", "-Pbench", "-pl", "testing/benchmarks", "-am", "package",
                 "-DskipTests", "-Djacoco.skip=true"], cwd=ROOT)
        if r.returncode != 0:
            return {"error": "build failed: " + r.stdout[-500:]}
    out = os.path.join(args.out, "jmh.json")
    r = run(["java", "--add-exports", "java.base/jdk.internal.misc=ALL-UNNAMED", "-jar", jar, "-wi", "2", "-i", "3",
             "-f", "1", "-w", "2s", "-r", "3s", "-rf", "json", "-rff", out])
    if r.returncode != 0:
        return {"error": r.stdout[-500:]}
    data = json.load(open(out))
    return [{"benchmark": b["benchmark"], "mode": b["mode"], "score": round(b["primaryMetric"]["score"], 3),
             "error": round(b["primaryMetric"]["scoreError"], 3), "unit": b["primaryMetric"]["scoreUnit"]}
            for b in data]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--steps", default="500,1000,2000,4000,8000,16000", help="request rates per second")
    p.add_argument("--duration", type=int, default=60, help="seconds per step")
    p.add_argument("--interim", type=int, default=10, help="interim interval of the accounting sessions")
    p.add_argument("--generators", type=int, default=4, help="load containers per step")
    p.add_argument("--max-generators", type=int, default=8,
                   help="a step short of its rate with latency fine is repeated with up to this many")
    p.add_argument("--resolution", type=float, default=0.1,
                   help="bisect between the last good and the failed step down to this share of the rate")
    p.add_argument("--workloads", default="accounting,access,mix")
    p.add_argument("--p99-limit", type=float, default=500.0, help="ms; above it a step fails")
    p.add_argument("--pause", type=int, default=10, help="seconds between steps")
    p.add_argument("--image", default=os.environ.get("RADIUSWARD_IMAGE", "radiusward:dev"))
    p.add_argument("--where", default=os.environ.get("BENCH_WHERE", "local"), help="label of the environment")
    p.add_argument("--out", default=os.path.join(ROOT, "testing/benchmarks/target/bench"))
    p.add_argument("--external", action="store_true", help="use the running compose stack, leave it running")
    p.add_argument("--external-generators", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--monitoring", action="store_true", help="also start Prometheus and Grafana")
    p.add_argument("--no-failover", action="store_true")
    p.add_argument("--jmh", action="store_true", help="also run the JMH micro-benchmarks")
    p.add_argument("--quick", action="store_true", help="20 s steps, 250 → 4000/s, no failover")
    p.add_argument("--secret", default="testing123", help="the NAS entry's shared secret")
    p.add_argument("--target", help="gateway addresses of a remote stack (the ECS load balancers); implies --external")
    p.add_argument("--ecs-cluster", help="with --target: the ECS cluster, for the tasks' metrics and the failover")
    p.add_argument("--generator-hosts", type=lambda v: v.split(","), default=None,
                   help="where the generators run, round robin: 'local' or EC2 instance ids (through SSM)")
    p.add_argument("--label", action="append", default=[], help="key=value recorded in the environment")
    args = p.parse_args()
    global STACK, ARGS
    ARGS = args
    if args.target:
        if not args.ecs_cluster:
            sys.exit("--target needs --ecs-cluster")
        args.external = True
        STACK = EcsStack(args)
    else:
        STACK = LocalStack(args)
    if args.quick:
        args.steps, args.duration, args.pause, args.no_failover = "250,500,1000,2000,4000", 20, 5, True
    steps = [int(s) for s in args.steps.split(",")]
    os.makedirs(args.out, exist_ok=True)
    os.environ["RADIUSWARD_IMAGE"] = args.image

    if not args.external:
        log(f"starting the compose stack ({args.image})")
        compose("down", "-v", profiles=["monitoring", "backup"])
        r = compose("up", "-d", "--wait", profiles=["monitoring"] if args.monitoring else ())
        if r.returncode != 0:
            sys.exit("compose up failed:\n" + r.stdout + r.stderr)
    result = {"schema": 2, "environment": environment(args, args.image),
              "settings": {"steps": steps, "duration_s": args.duration, "generators": args.generators,
                           "max_generators": args.max_generators, "resolution": args.resolution,
                           "p99_limit_ms": args.p99_limit, "interim_s": args.interim}, "workloads": {}}
    try:
        for i, w in enumerate(args.workloads.split(",")):
            # session ids are 32-bit: workloads 400M apart, probes 20M, generators 2M
            result["workloads"][w] = ladder(w, steps, args, args.image, i * 400_000_000)
        ceiling = result["workloads"].get("accounting", {}).get("ceiling_rps", 0)
        if not args.no_failover:
            result["failover"] = failover(ceiling, args, args.image)
        if args.jmh:
            result["jmh"] = jmh(args)
    finally:
        name = os.path.join(args.out, f"bench-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
        json.dump(result, open(name, "w"), indent=2)
        log(f"result: {name}")
        for w, r in result["workloads"].items():
            log(f"  {w:<10} ceiling {'≥ ' if r.get('load_limited') else ''}{r['ceiling_rps']}/s"
                + (" (load-limited: the generators or the host, not radiusward)" if r.get("load_limited") else ""))
        if not args.external:
            compose("down", "-v", profiles=["monitoring", "backup"])


if __name__ == "__main__":
    main()
