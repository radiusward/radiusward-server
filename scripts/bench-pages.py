#!/usr/bin/env python3
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
"""Benchmark pages (B3 of docs/plans/benchmarks.md, ADR 0066).

Adds every bench-*.json under <results> to <site>/benchmarks/ (raw results, history.json), then writes
<site>/benchmarks/index.html — ceilings and failover of the latest run per environment, the ladders as charts, CPU per
container at the top step, the trend of the ceilings and of the JMH scores — latest.json for the landing page and
<site>/badges/bench.json. Plain HTML and inline SVG, no scripts.

  scripts/bench-pages.py <results> <site>
"""

import glob
import html
import json
import os
import sys

WORKLOADS = [("accounting", "Accounting", "Start and Interim records of fresh sessions through both gateways"),
             ("access", "Authentication", "Access-Requests with PAP, CHAP and MS-CHAPv2"),
             ("mix", "Mix", "70 % accounting, 30 % authentication")]
COLORS = ["#2f6fdb", "#d9822b", "#1a7f37", "#8250df", "#cf222e", "#0a7ea4", "#9a6700"]


def load_runs(results, bench_dir):
    os.makedirs(os.path.join(bench_dir, "runs"), exist_ok=True)
    for path in glob.glob(os.path.join(results, "**", "bench-*.json"), recursive=True):
        target = os.path.join(bench_dir, "runs", os.path.basename(path))
        if not os.path.exists(target):
            with open(path) as src, open(target, "w") as dst:
                dst.write(src.read())
    runs = []
    for path in sorted(glob.glob(os.path.join(bench_dir, "runs", "bench-*.json"))):
        try:
            run = json.load(open(path))
        except ValueError:
            continue
        run["_file"] = "runs/" + os.path.basename(path)
        runs.append(run)
    runs.sort(key=lambda r: r["environment"].get("date", ""))
    return runs


def esc(value):
    return html.escape(str(value))


def fmt(n):
    return f"{n:,.0f}" if isinstance(n, (int, float)) else "–"


def chart(series, x_label, y_label, width=560, height=260, log_x=False, y_max=None, x_dates=False):
    """series: [(name, [(x, y), ...])]. Returns an inline SVG line chart."""
    import math
    pts = [p for _, s in series for p in s if p[1] is not None]
    if not pts:
        return '<p class="muted">no data yet</p>'
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    fx = (lambda v: math.log10(v)) if log_x else (lambda v: v)
    x0, x1 = fx(min(xs)), fx(max(xs))
    if x0 == x1:
        x0, x1 = x0 - 1, x1 + 1
    y1 = y_max or max(ys) * 1.1 or 1
    left, right, top, bottom = 64, 16, 14, 40
    w, h = width - left - right, height - top - bottom

    def px(v):
        return left + (fx(v) - x0) / (x1 - x0) * w

    def py(v):
        return top + h - min(v, y1) / y1 * h

    out = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" aria-label="{esc(y_label)}">']
    for i in range(5):
        v = y1 * i / 4
        y = py(v)
        out.append(f'<line x1="{left}" x2="{left + w}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                   f'<text x="{left - 6}" y="{y + 4:.1f}" class="tick" text-anchor="end">{fmt(v)}</text>')
    ticks = sorted(set(xs))
    if x_dates:
        ticks = ticks[:: max(1, len(ticks) // 6)]
    for v in ticks:
        x = px(v)
        label = v if not x_dates else ""
        out.append(f'<text x="{x:.1f}" y="{top + h + 16}" class="tick" text-anchor="middle">'
                   f'{esc(fmt(label) if not x_dates else "")}</text>')
    out.append(f'<text x="{left + w / 2}" y="{height - 4}" class="axis" text-anchor="middle">{esc(x_label)}</text>')
    out.append(f'<text x="14" y="{top + h / 2}" class="axis" text-anchor="middle" '
               f'transform="rotate(-90 14 {top + h / 2})">{esc(y_label)}</text>')
    for i, (name, s) in enumerate(series):
        s = [p for p in s if p[1] is not None]
        if not s:
            continue
        color = COLORS[i % len(COLORS)]
        if len(s) > 1:
            path = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y in s)
            out.append(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="2"/>')
        for x, y in s:
            out.append(f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="3" fill="{color}"><title>{esc(name)}: '
                       f'{fmt(y)} at {esc(x if not x_dates else "")}</title></circle>')
    out.append("</svg>")
    legend = " ".join(f'<span class="key"><i style="background:{COLORS[i % len(COLORS)]}"></i>{esc(n)}</span>'
                      for i, (n, _) in enumerate(series))
    return '<div class="plot">' + "".join(out) + f'<div class="legend">{legend}</div></div>'


def env_label(env):
    d = env.get("docker") or {}
    return f'{env.get("where", "?")} · {d.get("cpus", "?")} vCPU {d.get("arch", "")}'.strip()


def latest_per_environment(runs):
    latest = {}
    for run in runs:
        latest[run["environment"].get("where", "?")] = run
    return latest


def run_section(run):
    env = run["environment"]
    commit = env.get("commit", "")
    parts = [f'<section class="card"><h2>{esc(env_label(env))}</h2>',
             f'<p class="muted">{esc(env.get("date", ""))} · commit '
             f'<a href="https://github.com/radiusward/radiusward-server/commit/{esc(commit)}">{esc(commit[:7])}</a> · '
             f'{esc(env.get("java", ""))} · profile {esc(env.get("profile", ""))} · '
             f'<a href="{esc(run["_file"])}">raw JSON</a></p>']
    if env.get("shared_host"):
        parts.append('<p class="note">Members, gateways and load generators shared this machine\'s CPUs: a lower '
                     'bound, not the ceiling of separate machines.</p>')
    rows = []
    for key, title, _ in WORKLOADS:
        w = run.get("workloads", {}).get(key)
        if not w:
            continue
        last_ok = [s for s in w["steps"] if not s.get("problems")]
        p99 = last_ok[-1]["p99_ms"] if last_ok else None
        stop = next((s for s in w["steps"] if s.get("problems")), None)
        why = "; ".join(stop["problems"]) if stop else "every step passed (raise --steps)"
        rows.append(f"<tr><td>{esc(title)}</td><td class='num'><b>{fmt(w['ceiling_rps'])}/s</b></td>"
                    f"<td class='num'>{fmt(p99)} ms</td><td>{esc(why)}</td></tr>")
    parts.append("<table><tr><th>Workload</th><th>Ceiling</th><th>p99 there</th><th>Next step</th></tr>"
                 + "".join(rows) + "</table>")
    f = run.get("failover")
    if f and "accounting" in f:
        a = f["accounting"]
        verdict = "nothing lost" if not f.get("problems") else "; ".join(f["problems"])
        parts.append(f'<p><b>Leader killed at {fmt(f["target_rps"])}/s:</b> {esc(verdict)}, '
                     f'{fmt(a.get("retransmissions"))} retransmissions, longest wait {fmt(a.get("max_ms"))} ms.</p>')
    for key, title, what in WORKLOADS:
        w = run.get("workloads", {}).get(key)
        if not w:
            continue
        steps = w["steps"]
        parts.append(f'<h3>{esc(title)}</h3><p class="muted">{esc(what)}</p><div class="pair">')
        parts.append(chart([("target", [(s["target_rps"], s["target_rps"]) for s in steps]),
                            ("achieved", [(s["target_rps"], s.get("rps")) for s in steps])],
                           "target requests/s", "requests/s", log_x=True))
        parts.append(chart([("p99", [(s["target_rps"], s.get("p99_ms")) for s in steps]),
                            ("limit", [(s["target_rps"], run["settings"].get("p99_limit_ms", 500)) for s in steps])],
                           "target requests/s", "p99 latency, ms", log_x=True))
        parts.append("</div>")
        top = steps[-1]
        containers = top.get("containers", {})
        if containers:
            cells = "".join(f"<tr><td>{esc(n)}</td><td class='num'>{c['cpu_avg_pct']:.0f} %</td>"
                            f"<td class='num'>{c['cpu_max_pct']:.0f} %</td>"
                            f"<td class='num'>{c['mem_max_bytes'] / 2**20:,.0f} MiB</td></tr>"
                            for n, c in containers.items())
            parts.append(f'<details><summary>CPU and memory per container at {fmt(top["target_rps"])}/s</summary>'
                         f"<table><tr><th>Container</th><th>CPU avg</th><th>CPU max</th><th>Memory</th></tr>"
                         f"{cells}</table></details>")
    jmh = run.get("jmh")
    if isinstance(jmh, list) and jmh:
        cells = "".join(f"<tr><td>{esc(b['benchmark'].split('.')[-1])}</td><td class='num'>{b['score']:,.3f} "
                        f"± {b['error']:,.3f}</td><td>{esc(b['unit'])}</td></tr>" for b in jmh)
        parts.append(f"<h3>Micro-benchmarks (JMH, one core)</h3><table><tr><th>Benchmark</th><th>Score</th>"
                     f"<th>Unit</th></tr>{cells}</table>")
    parts.append("</section>")
    return "".join(parts)


def trend_section(runs):
    by_env = {}
    for run in runs:
        by_env.setdefault(run["environment"].get("where", "?"), []).append(run)
    parts = ['<section class="card"><h2>Trend</h2>']
    for where, rs in by_env.items():
        if len(rs) < 1:
            continue
        idx = list(range(1, len(rs) + 1))
        series = [(title, [(i, r.get("workloads", {}).get(key, {}).get("ceiling_rps")) for i, r in zip(idx, rs)])
                  for key, title, _ in WORKLOADS]
        dates = ", ".join(f"{i}: {r['environment'].get('date', '')[:10]} {r['environment'].get('commit', '')[:7]}"
                          for i, r in zip(idx, rs))
        parts.append(f"<h3>Ceilings · {esc(where)}</h3>" + chart(series, "run", "ceiling, requests/s")
                     + f'<p class="muted small">runs {esc(dates)}</p>')
        names = sorted({b["benchmark"].split(".")[-1] for r in rs if isinstance(r.get("jmh"), list) for b in r["jmh"]})
        if names:
            jseries = [(n, [(i, next((b["score"] for b in (r.get("jmh") or []) if b["benchmark"].endswith("." + n)),
                                     None)) for i, r in zip(idx, rs)]) for n in names]
            parts.append(f"<h3>JMH · {esc(where)}</h3>" + chart(jseries, "run", "operations per µs"))
    parts.append("</section>")
    return "".join(parts)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>radiusward benchmarks</title>
<style>
:root {{ --bg:#f6f7f9; --fg:#1d2330; --muted:#5c6577; --card:#fff; --line:#dfe3ea; --grid:#e8ebf0; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1218; --fg:#e6e9ef; --muted:#9aa3b5; --card:#181c24;
  --line:#2a303c; --grid:#262c37; }} }}
* {{ box-sizing:border-box }} body {{ margin:0; background:var(--bg); color:var(--fg);
  font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif }}
main {{ max-width:1180px; margin:0 auto; padding:32px 16px }} a {{ color:inherit }}
h1 {{ margin:0 0 4px; font-size:28px }} h2 {{ margin:0 0 4px; font-size:21px }} h3 {{ margin:20px 0 2px; font-size:17px }}
.lead,.muted {{ color:var(--muted) }} .small {{ font-size:13px }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px 20px; margin:16px 0 }}
.note {{ border-left:4px solid #d9822b; padding:4px 10px; color:var(--muted); font-size:14px }}
table {{ border-collapse:collapse; width:100%; margin:8px 0; font-size:14px }}
th,td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top }}
.num {{ text-align:right; white-space:nowrap }}
.pair {{ display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(min(100%,480px),1fr)) }}
.chart {{ width:100%; height:auto }} .grid {{ stroke:var(--grid) }}
.tick {{ font-size:11px; fill:var(--muted) }} .axis {{ font-size:12px; fill:var(--muted) }}
.legend {{ font-size:13px; color:var(--muted) }} .key {{ margin-right:14px; white-space:nowrap }}
.key i {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px }}
details {{ margin:8px 0 }} summary {{ cursor:pointer; color:var(--muted); font-size:14px }}
</style></head>
<body><main>
<p><a href="../">← test reports</a></p>
<h1>radiusward benchmarks</h1>
<p class="lead">How much radiusward carries: ladders of rising request rates until a request is lost, the p99 passes
the limit or the rate no longer arrives (the last good step is the ceiling), a leader kill at 70 % of the accounting
ceiling, and the JMH micro-benchmarks — measured by <code>scripts/bench.py</code> the same way everywhere
(<a href="https://github.com/radiusward/radiusward-server/blob/main/docs/testing/benchmarks.md">how</a>,
<a href="https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0066-benchmarks.md">ADR 0066</a>).</p>
{sections}
{trend}
</main></body></html>
"""


def main():
    results, site = sys.argv[1], sys.argv[2]
    bench_dir = os.path.join(site, "benchmarks")
    os.makedirs(bench_dir, exist_ok=True)
    runs = load_runs(results, bench_dir)
    if not runs:
        print("benchmarks: no results yet")
        return
    latest = latest_per_environment(runs)
    sections = "".join(run_section(r) for r in sorted(latest.values(),
                                                       key=lambda r: r["environment"].get("date", ""), reverse=True))
    open(os.path.join(bench_dir, "index.html"), "w").write(PAGE.format(sections=sections, trend=trend_section(runs)))
    newest = runs[-1]
    summary = {"where": newest["environment"].get("where"), "date": newest["environment"].get("date"),
               "commit": newest["environment"].get("commit"), "environment": env_label(newest["environment"]),
               "ceilings": {k: newest.get("workloads", {}).get(k, {}).get("ceiling_rps") for k, _, _ in WORKLOADS},
               "failover_lost": bool(newest["failover"].get("problems")) if newest.get("failover") else None,
               "runs": len(runs)}
    json.dump(summary, open(os.path.join(bench_dir, "latest.json"), "w"))
    os.makedirs(os.path.join(site, "badges"), exist_ok=True)
    acct = summary["ceilings"].get("accounting")
    json.dump({"schemaVersion": 1, "label": "benchmark",
               "message": f"accounting {acct:,.0f}/s ({summary['where']})" if acct else "no result",
               "color": "blue"}, open(os.path.join(site, "badges", "bench.json"), "w"))
    print(f"benchmarks: {len(runs)} run(s), latest {summary['where']} {summary['date']}: {summary['ceilings']}")


if __name__ == "__main__":
    main()
