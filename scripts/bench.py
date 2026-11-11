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
"""

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
        "shared_host": not args.external_generators,
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

    def __init__(self, interval=3):
        self.interval, self.samples, self._stop = interval, {}, threading.Event()
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
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
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


def scrape(port):
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as r:
            text = r.read().decode()
    except Exception:
        return {}
    values = {}
    for line in text.splitlines():
        for key, pattern in (("heap_used_bytes", r'^radiusward_jvm_memory_used_bytes\{area="heap"\} (\S+)'),
                             ("direct_bytes", r'^radiusward_jvm_buffer_used_bytes\{pool="direct"\} (\S+)'),
                             ("gc_pause_seconds_total", r'^radiusward_jvm_gc_pause_seconds_total\{[^}]*\} (\S+)'),
                             ("log_position_bytes", r'^radiusward_cluster_log_position_bytes\{[^}]*\} (\S+)'),
                             ("sessions_active", r'^radiusward_sessions\{[^}]*state="active"\} (\S+)')):
            m = re.match(pattern, line)
            if m:
                values[key] = values.get(key, 0) + float(m.group(1))
    return values


def generators(workload, rate, seconds, count, image, first_session, interim):
    """Starts `count` load containers sharing `rate` requests/s; returns their outputs."""
    per = max(1, rate // count)
    procs = []
    for g in range(count):
        args = ["radclient", "load", "--server", ",".join(f"{gw}:1813" for gw in GATEWAYS), "--retry-other-server",
                "--secret", "testing123", "--nas", "20", "--duration", f"{seconds}s", "--timeout", "3s",
                "--retries", "3", "--first-session", str(first_session + g * 4_000_000)]
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
        run(["docker", "rm", "-f", name])
        procs.append(subprocess.Popen(["docker", "run", "--rm", "--name", name, "--network", NETWORK, image] + args,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
    return [p.communicate()[0] for p in procs]


def combine(outputs, target, workload):
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
            "rps": round(sum(l[5] for l in loads), 1),
            "p50_ms": round(statistics.median(l[6] for l in loads), 1), "p99_ms": round(max(l[7] for l in loads), 1),
            "max_ms": round(max(l[8] for l in loads), 1)}
        rps += step["accounting"]["rps"]
        p99s.append(step["accounting"]["p99_ms"])
        p50s.append(step["accounting"]["p50_ms"])
    if accesses:
        seconds = max((l[4] for l in loads), default=0) or None
        sent = int(sum(a[0] for a in accesses))
        step["access"] = {
            "sent": sent, "accepted": int(sum(a[2] for a in accesses)), "rejected": int(sum(a[3] for a in accesses)),
            "timeouts": int(sum(a[5] for a in accesses)), "unexpected": int(sum(a[6] for a in accesses)),
            "p50_ms": round(statistics.median(a[7] for a in accesses), 1),
            "p99_ms": round(max(a[8] for a in accesses), 1)}
        if seconds:
            step["access"]["rps"] = round(sent / seconds, 1)
            rps += step["access"]["rps"]
        p99s.append(step["access"]["p99_ms"])
    step["rps"] = round(rps, 1)
    step["p99_ms"] = max(p99s) if p99s else None
    if not loads and not accesses:
        step["error"] = "no generator summary: " + " | ".join(o.strip().splitlines()[-1] if o.strip() else "" for o in outputs)
    return step


def verdict(step, limit_ms):
    reasons = []
    if "error" in step:
        reasons.append(step["error"])
    a, x = step.get("accounting", {}), step.get("access", {})
    if a.get("failed"):
        reasons.append(f"{a['failed']} accounting requests lost")
    if x.get("timeouts") or x.get("unexpected"):
        reasons.append(f"{x.get('timeouts', 0)} Access-Request timeouts, {x.get('unexpected', 0)} wrong answers")
    if step.get("p99_ms") is not None and step["p99_ms"] > limit_ms:
        reasons.append(f"p99 {step['p99_ms']} ms > {limit_ms} ms")
    if step.get("rps") and step["rps"] < 0.9 * step["target_rps"]:
        reasons.append(f"only {step['rps']} of {step['target_rps']} requests/s arrived")
    return reasons


def ladder(workload, steps, args, image, first):
    log(f"{workload}: ladder {steps}")
    results, ceiling = [], 0
    for i, rate in enumerate(steps):
        with Sampler() as sampler:
            outputs = generators(workload, rate, args.duration, args.generators, image, first + i * 40_000_000,
                                 args.interim)
        step = combine(outputs, rate, workload)
        step["containers"] = sampler.summary()
        step["members"] = {f"node-{n}": scrape(p) for n, p in enumerate(MEMBER_PORTS)}
        step["gateways"] = {f"gateway-{n}": scrape(p) for n, p in enumerate(GATEWAY_PORTS)}
        step["problems"] = verdict(step, args.p99_limit)
        results.append(step)
        log(f"  {rate:>6}/s → {step['rps']:>8}/s, p99 {step['p99_ms']} ms"
            + (f"  ✗ {'; '.join(step['problems'])}" if step["problems"] else "  ✓"))
        if step["problems"]:
            break
        ceiling = step["rps"]
        time.sleep(args.pause)
    return {"steps": results, "ceiling_rps": ceiling}


def leader():
    for n, port in enumerate(MEMBER_PORTS):
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/ready", timeout=3) as r:
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
            run(["docker", "kill", f"radiusward-node-{n}-1"])
            log(f"  killed member {n}")

    killer = threading.Thread(target=kill)
    killer.start()
    with Sampler():
        outputs = generators("accounting", rate, max(90, args.duration), args.generators, image, 2_000_000_000,
                             args.interim)
    killer.join()
    step = combine(outputs, rate, "accounting")
    step["killed_member"] = victim.get("member")
    step["problems"] = verdict(step, 10_000)  # a failover is allowed its gap; losses are not
    log(f"  {step['rps']}/s, max {step.get('accounting', {}).get('max_ms')} ms, "
        f"{step.get('accounting', {}).get('retransmissions')} retransmissions"
        + (f"  ✗ {'; '.join(step['problems'])}" if step["problems"] else "  ✓ nothing lost"))
    compose("up", "-d", "--wait", profiles=["monitoring"] if args.monitoring else ())
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
    args = p.parse_args()
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
    result = {"schema": 1, "environment": environment(args, args.image),
              "settings": {"steps": steps, "duration_s": args.duration, "generators": args.generators,
                           "p99_limit_ms": args.p99_limit, "interim_s": args.interim}, "workloads": {}}
    try:
        for i, w in enumerate(args.workloads.split(",")):
            # session ids are 32-bit: workloads 400M apart, steps 40M, generators 4M
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
            log(f"  {w:<10} ceiling {r['ceiling_rps']}/s")
        if not args.external:
            compose("down", "-v", profiles=["monitoring", "backup"])


if __name__ == "__main__":
    main()
