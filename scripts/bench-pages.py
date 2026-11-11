#!/usr/bin/env python3
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
"""Benchmark pages (B3 of docs/plans/benchmarks.md, ADR 0066).

Adds every bench-*.json under <results> to <site>/benchmarks/ (raw results, history.json), then writes
<site>/benchmarks/index.html — ceilings and failover of the latest run per environment, the ladders as charts, CPU per
container at the top step, the trend of the ceilings and of the JMH scores — latest.json for the landing page and
<site>/badges/bench.json. Plain HTML and inline SVG, no scripts (only JSON-LD data for search engines). The summary,
landing card and badge show the newest run on dedicated machines (AWS) when there is one, else the newest run.

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


def ms(n):
    return f"{n:.1f}" if isinstance(n, (int, float)) and n < 10 else fmt(n)


def per_rate(steps):
    """One step per target rate, ascending; a rate probed again (more generators, a bisection) shows its last probe."""
    final = {}
    for step in steps:
        final[step["target_rps"]] = step
    return [final[rate] for rate in sorted(final)]


def pretty(reason):
    """A harness reason in plain words: 'p99 609.3 ms > 500.0 ms' → 'p99 609 ms, over 500 ms'."""
    import re
    reason = re.sub(r"p99 ([\d.]+) ms > ([\d.]+) ms",
                    lambda m: f"p99 {float(m.group(1)):,.0f} ms, over {float(m.group(2)):,.0f} ms", reason)
    return re.sub(r"only ([\d.]+) of (\d+) requests/s arrived",
                  lambda m: f"only {float(m.group(1)):,.0f} of {int(m.group(2)):,}/s answered", reason)


def lower_bound(w):
    """The ceiling is only a lower bound: the load ran out, or every step passed (schema 2 records stopped_by)."""
    return bool(w.get("load_limited")) or ("stopped_by" in w and not w["stopped_by"])


def ceiling_text(w):
    return f"{'≥ ' if lower_bound(w) else ''}{fmt(w['ceiling_rps'])}/s"


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
    last = None
    for v in ticks:
        x = px(v)
        if last is not None and x - last < 34:
            continue  # bisected rates lie close together; their values are in the steps table
        last = x
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


def featured(runs):
    """The run the summary, the landing page and the badge show: the newest on dedicated machines (AWS), else the
    newest of all."""
    dedicated = [r for r in runs if not r["environment"].get("shared_host")]
    return (dedicated or runs)[-1]


# what each micro-benchmark covers (testing/benchmarks CodecBenchmark, a ~200-byte Cisco Interim-Update)
JMH = {"validate": "structure check of the packet and its attributes",
       "verifyAuthenticator": "the Request Authenticator (MD5 over the packet and the shared secret)",
       "extract": "the attributes accounting needs, read without allocating",
       "encodeResponse": "the Accounting-Response, signed",
       "fullReceivePath": "all of the above: what a gateway does per accounting packet before the cluster commit"}


def at_ceiling(w):
    return next((s for s in w["steps"] if s.get("rps") == w["ceiling_rps"]), None)


def p50(step):
    values = [step[k]["p50_ms"] for k in ("accounting", "access") if step.get(k, {}).get("p50_ms") is not None]
    return max(values) if values else None


def kpi(value, title, lines, tone=""):
    body = "".join(f"<li>{line}</li>" for line in lines)
    return f'<div class="kpi {tone}"><div class="value">{value}</div><div class="title">{esc(title)}</div><ul>{body}</ul></div>'


def kpis(run):
    cards = []
    texts = {"accounting": ("Accounting", "committed on two of three members with fsync before each Accounting-Response"),
             "access": ("Authentication", "Access-Requests with PAP, CHAP and MS-CHAPv2, decided by the gateways"),
             "mix": ("Mixed load", "70 % accounting, 30 % authentication")}
    for key, (title, what) in texts.items():
        w = run.get("workloads", {}).get(key)
        if not w or not w.get("ceiling_rps"):
            continue
        at = at_ceiling(w) or {}
        lines = [esc(what), f"p99 {ms(at.get('p99_ms'))} ms, p50 {ms(p50(at))} ms"]
        if w.get("load_limited"):
            lines.append("a lower bound: the load could not be raised further")
        elif not w.get("stopped_by"):
            lines.append("every step passed: the limit is higher")
        else:
            lines.append(f"the next step failed: {esc(pretty(w['stopped_by']))}")
        prefix = "≥ " if lower_bound(w) else ""
        cards.append(kpi(f"{prefix}{fmt(w['ceiling_rps'])}<small>/s</small>", title, lines))
    f = run.get("failover")
    if f and "accounting" in f:
        a = f["accounting"]
        ok = not f.get("problems")
        cards.append(kpi(f"{fmt(a.get('failed', 0))}<small> lost</small>", "Leader killed under load",
                         [f"the cluster leader killed at {fmt(f['target_rps'])} accounting requests/s",
                          f"{fmt(a.get('retransmissions'))} retransmissions, longest wait {fmt(a.get('max_ms'))} ms",
                          "every acknowledged record kept" if ok else esc("; ".join(f["problems"]))],
                         "good" if ok else "bad"))
    return '<div class="kpis">' + "".join(cards) + "</div>"


def machine_note(run):
    env = run["environment"]
    names = set()
    for w in run.get("workloads", {}).values():
        for s in w["steps"]:
            names.update(s.get("containers", {}).keys())
    generators = len({n for n in names if n.startswith("bench-gen")})
    labels = env.get("labels") or {}
    if env.get("shared_host"):
        cpus = (env.get("docker") or {}).get("cpus", "?")
        return (f'<p class="note"><b>One shared machine, {esc(cpus)} vCPU:</b> three cluster members, two gateways, '
                f'PostgreSQL with the exporter and {generators or "the"} load generators all ran on it, each member and '
                f'gateway limited to one CPU. The numbers are a lower bound and a trend from week to week; separate '
                f'machines carry more.</p>')
    parts = [f"{k.replace('_', ' ')} {v}" for k, v in labels.items()]
    return (f'<p class="note good"><b>Dedicated machines:</b> members, gateways and load generators on their own '
            f'instances{": " + esc(", ".join(parts)) if parts else ""}.</p>')


def memory_note(run):
    peak = {"gateway": 0, "node": 0}
    for w in run.get("workloads", {}).values():
        for s in w["steps"]:
            for name, c in s.get("containers", {}).items():
                for role in peak:
                    if name.startswith(role):
                        peak[role] = max(peak[role], c.get("mem_max_bytes", 0))
    if not any(peak.values()):
        return ""
    return (f'<p><b>Memory at the highest load:</b> each gateway at most {fmt(peak["gateway"] / 2**20)} MiB, each '
            f'cluster member at most {fmt(peak["node"] / 2**20)} MiB (profile {esc(run["environment"].get("profile", ""))}, '
            f'which fits a member in 1 GiB).</p>')


def caption(title, w, limit):
    at = at_ceiling(w)
    steps = per_rate(w["steps"])
    first = steps[0] if steps else None
    if not at or not first:
        return ""
    text = (f"{title}: from {fmt(first['target_rps'])}/s (p99 {fmt(first.get('p99_ms'))} ms) up to "
            f"{fmt(w['ceiling_rps'])}/s (p99 {fmt(at.get('p99_ms'))} ms)")
    if w.get("stopped_by"):
        text += f"; the next step failed: {pretty(w['stopped_by'])}"
    else:
        text += f"; every step stayed within {fmt(limit)} ms"
    return f"<figcaption>{esc(text)}.</figcaption>"


def steps_table(w, limit):
    order = {id(s): i + 1 for i, s in enumerate(w["steps"])}
    rows = []
    for s in sorted(w["steps"], key=lambda s: (s["target_rps"], order[id(s)])):
        if s.get("problems"):
            verdict = "✗ " + "; ".join(pretty(p) for p in s["problems"]) + (" (load-limited)" if s.get("load_limited") else "")
        else:
            verdict = "✓ passed" + (" — the ceiling" if s.get("rps") == w["ceiling_rps"] else "")
        cls = " class='best'" if s.get("rps") == w["ceiling_rps"] and not s.get("problems") else ""
        rows.append(f"<tr{cls}><td class='num'>{fmt(s['target_rps'])}/s</td><td class='num'>{fmt(s.get('rps'))}/s</td>"
                    f"<td class='num'>{fmt(s.get('p99_ms'))} ms</td><td class='num'>{order[id(s)]}</td>"
                    f"<td class='num'>{s.get('generators', '')}</td><td>{esc(verdict)}</td></tr>")
    return (f"<details><summary>Every step, by rate</summary><p class='muted small'>After the first failed step the "
            f"harness bisects between the last good and the failed rate, so the run order (#) is not ascending. A step "
            f"passes with nothing lost, p99 under {fmt(limit)} ms and at least 90 % of the rate answered.</p>"
            f"<table><tr><th class='num'>Target</th><th class='num'>Answered</th><th class='num'>p99</th><th class='num'>#</th>"
            f"<th class='num'>Generators</th><th>Result</th></tr>"
            + "".join(rows) + "</table></details>")


def jmh_table(jmh):
    rows = []
    order = list(JMH)  # the packet's way through the gateway, the whole path first
    order.insert(0, order.pop())
    for b in sorted(jmh, key=lambda b: order.index(b["benchmark"].split(".")[-1])
                    if b["benchmark"].split(".")[-1] in order else len(order)):
        name = b["benchmark"].split(".")[-1]
        score = b["score"]
        if b.get("unit") != "ops/us" or not score:
            continue
        noisy = b.get("error") and b["error"] > score / 2
        rows.append(f"<tr><td><code>{esc(name)}</code></td><td>{esc(JMH.get(name, ''))}</td>"
                    f"<td class='num'>{1000 / score:,.0f} ns</td><td class='num'>{score * 1e6:,.0f}/s</td>"
                    f"<td class='num'>± {100 * b.get('error', 0) / score:.0f} %{' (noisy)' if noisy else ''}</td></tr>")
    if not rows:
        return ""
    return ("<h3>The gateway's packet path on one core (JMH)</h3><p class='muted small'>Per accounting packet of about "
            "200 bytes, on one core of this machine, without the network and without the cluster commit. Short runs on "
            "a shared machine are noisy; the trend below shows them over time.</p><table><tr><th>Step</th><th>What it "
            "does</th><th class='num'>Per packet</th><th class='num'>Per second, one core</th><th class='num'>Error</th></tr>" + "".join(rows) + "</table>")


def run_section(run):
    env = run["environment"]
    commit = env.get("commit", "")
    limit = run["settings"].get("p99_limit_ms", 500)
    parts = [f'<section class="card" id="{esc(env.get("where", ""))}"><h2>{esc(env_label(env))}</h2>',
             f'<p class="muted small">{esc(env.get("date", ""))} · commit '
             f'<a href="https://github.com/radiusward/radiusward-server/commit/{esc(commit)}">{esc(commit[:7])}</a> · '
             f'{esc(env.get("java", ""))} · profile {esc(env.get("profile", ""))} · '
             f'<a href="{esc(run["_file"])}">raw JSON</a></p>', machine_note(run), kpis(run), memory_note(run)]
    for key, title, what in WORKLOADS:
        w = run.get("workloads", {}).get(key)
        if not w:
            continue
        steps = per_rate(w["steps"])
        parts.append(f'<h3>{esc(title)}: {esc(ceiling_text(w))}</h3><p class="muted small">{esc(what)}</p>'
                     f'<figure><div class="pair">')
        parts.append(chart([("target", [(s["target_rps"], s["target_rps"]) for s in steps]),
                            ("answered", [(s["target_rps"], s.get("rps")) for s in steps])],
                           "target requests/s", "requests/s", log_x=True))
        parts.append(chart([("p99", [(s["target_rps"], s.get("p99_ms")) for s in steps]),
                            ("limit", [(s["target_rps"], limit) for s in steps])],
                           "target requests/s", "p99 latency, ms", log_x=True))
        parts.append("</div>" + caption(title, w, limit) + "</figure>")
        top = at_ceiling(w) or steps[-1]
        containers = top.get("containers", {})
        if containers:
            cells = "".join(f"<tr><td>{esc(n)}</td><td class='num'>{c['cpu_avg_pct']:.0f} %</td>"
                            f"<td class='num'>{c['cpu_max_pct']:.0f} %</td>"
                            f"<td class='num'>{c['mem_max_bytes'] / 2**20:,.0f} MiB</td></tr>"
                            for n, c in containers.items())
            parts.append(f'<details><summary>CPU and memory per process at {fmt(top["target_rps"])}/s, the ceiling '
                         f'(100 % = one core)</summary>'
                         f"<table><tr><th>Process</th><th class='num'>CPU avg</th><th class='num'>CPU max</th><th class='num'>Memory</th></tr>"
                         f"{cells}</table></details>")
        parts.append(steps_table(w, limit))
    jmh = run.get("jmh")
    if isinstance(jmh, list) and jmh:
        parts.append(jmh_table(jmh))
    parts.append("</section>")
    return "".join(parts)


def trend_section(runs):
    by_env = {}
    for run in runs:
        by_env.setdefault(run["environment"].get("where", "?"), []).append(run)
    parts = ['<section class="card"><h2>Trend</h2><p class="muted small">Every run per environment, to see whether a '
             'change made radiusward slower. On a shared machine single runs vary; read the direction, not one '
             'point.</p>']
    for where, rs in by_env.items():
        if len(rs) < 1:
            continue
        idx = list(range(1, len(rs) + 1))
        series = [(title, [(i, r.get("workloads", {}).get(key, {}).get("ceiling_rps")) for i, r in zip(idx, rs)])
                  for key, title, _ in WORKLOADS]
        dates = ", ".join(f"{i}: {r['environment'].get('date', '')[:10]} {r['environment'].get('commit', '')[:7]}"
                          for i, r in zip(idx, rs))
        parts.append(f'<h3>{esc(where)}</h3><div class="pair"><figure>{chart(series, "run", "ceiling, requests/s")}'
                     f'<figcaption>The ceilings per run.</figcaption></figure>')
        names = sorted({b["benchmark"].split(".")[-1] for r in rs if isinstance(r.get("jmh"), list) for b in r["jmh"]})
        if names:
            jseries = [(n, [(i, next((b["score"] for b in (r.get("jmh") or []) if b["benchmark"].endswith("." + n)),
                                     None)) for i, r in zip(idx, rs)]) for n in names]
            parts.append(f'<figure>{chart(jseries, "run", "packets per µs, one core")}'
                         f'<figcaption>The gateway\'s packet path (JMH) per run.</figcaption></figure>')
        parts.append(f'</div><p class="muted small">runs {esc(dates)}</p>')
    parts.append("</section>")
    return "".join(parts)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>radiusward benchmarks: RADIUS accounting and authentication throughput, failover under load</title>
<meta name="description" content="{description}">
<script type="application/ld+json">{{"@context": "https://schema.org", "@type": "SoftwareApplication",
 "name": "radiusward", "applicationCategory": "NetworkingApplication", "operatingSystem": "Linux, Docker, Kubernetes",
 "url": "https://github.com/radiusward/radiusward-server", "license": "https://www.apache.org/licenses/LICENSE-2.0",
 "description": "Open-source replicated RADIUS server: accounting acknowledged only after a majority commit, authentication with PAP, CHAP, MS-CHAP and EAP."}}</script>
<style>
:root {{ --bg:#f6f7f9; --fg:#1d2330; --muted:#5c6577; --card:#fff; --line:#dfe3ea; --grid:#e8ebf0; --accent:#2f6fdb;
  --good:#1a7f37; --bad:#cf222e; --warn:#d9822b; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1218; --fg:#e6e9ef; --muted:#9aa3b5; --card:#181c24;
  --line:#2a303c; --grid:#262c37; --accent:#58a6ff; --good:#3fb950; --bad:#f85149; }} }}
* {{ box-sizing:border-box }} body {{ margin:0; background:var(--bg); color:var(--fg);
  font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif }}
main {{ max-width:1180px; margin:0 auto; padding:24px 16px 48px }} a {{ color:inherit }}
h1 {{ margin:8px 0 6px; font-size:30px }} h2 {{ margin:0 0 4px; font-size:21px }} h3 {{ margin:24px 0 2px; font-size:17px }}
.lead {{ font-size:17px; max-width:900px }} .muted {{ color:var(--muted) }} .small {{ font-size:13px }}
.nav {{ display:flex; flex-wrap:wrap; gap:8px 18px; font-size:14px }} .nav a {{ text-decoration:none; font-weight:600 }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px 20px; margin:16px 0 }}
.rules {{ border-left:4px solid var(--accent); padding:4px 12px; margin:12px 0; font-size:15px; max-width:900px }}
.note {{ border-left:4px solid var(--warn); padding:4px 10px; color:var(--muted); font-size:14px }}
.note.good {{ border-left-color:var(--good) }}
.kpis {{ display:grid; gap:12px; margin:12px 0; grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr)) }}
.kpi {{ border:1px solid var(--line); border-top:4px solid var(--accent); border-radius:8px; padding:10px 14px }}
.kpi.good {{ border-top-color:var(--good) }} .kpi.bad {{ border-top-color:var(--bad) }}
.kpi .value {{ font-size:28px; font-weight:700; line-height:1.2 }} .kpi .value small {{ font-size:15px; font-weight:600 }}
.kpi .title {{ font-weight:600 }} .kpi ul {{ margin:6px 0 0; padding-left:18px; color:var(--muted); font-size:13px }}
table {{ border-collapse:collapse; width:100%; margin:8px 0; font-size:14px }}
th,td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top }}
tr.best td {{ font-weight:600 }} .num {{ text-align:right; white-space:nowrap }}
figure {{ margin:8px 0 }} figcaption {{ font-size:13px; color:var(--muted) }}
.pair {{ display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(min(100%,480px),1fr)) }}
.pair > *, .plot {{ min-width:0 }} .chart {{ width:100%; height:auto; display:block }} .grid {{ stroke:var(--grid) }}
.tick {{ font-size:11px; fill:var(--muted) }} .axis {{ font-size:12px; fill:var(--muted) }}
.legend {{ font-size:13px; color:var(--muted) }} .key {{ margin-right:14px; white-space:nowrap }}
.key i {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px }}
.scroll {{ overflow-x:auto; max-width:100% }} main {{ overflow-wrap:anywhere }}
details {{ margin:8px 0 }} summary {{ cursor:pointer; color:var(--muted); font-size:14px }}
pre {{ background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:10px; overflow-x:auto; font-size:13px }}
</style></head>
<body><main>
<nav class="nav"><a href="../">← All test reports</a><a href="https://github.com/radiusward/radiusward-server">GitHub ↗</a>
<a href="https://github.com/radiusward/radiusward-server/blob/main/docs/testing/benchmarks.md">Run it yourself ↗</a></nav>
<h1>radiusward benchmarks</h1>
<p class="lead">radiusward is an open-source RADIUS server that replicates accounting over a three-member cluster: an
Accounting-Response goes out only once the record is stored with fsync on a majority, so a crashed node loses nothing
that was acknowledged. This page shows how much load it carries, how fast it answers, and what a crash of the cluster
leader costs under load — measured with the same open harness in every environment.</p>
<p class="rules"><b>How a result is measured:</b> the request rate rises step by step. A step passes only if
<b>no request is lost</b>, <b>99 % of the answers come within 500 ms</b> (p99) and at least 90 % of the target rate is
answered. The highest passing rate is the ceiling; "≥" marks a lower bound, where the limit lies higher.</p>
{sections}
{trend}
<section class="card"><h2>More evidence and reproducing it</h2>
<p>The same properties under faults: <a href="../linux/">fault injection</a> (power loss with LazyFS, partitions, full
disk, a PostgreSQL outage), <a href="../k8s/">Kubernetes</a> (leader killed, rolling updates, a volume replaced, a lost
quorum restored), <a href="../e2e/">end-to-end</a> and <a href="../integration/">integration</a> tests.</p>
<p>Every number here comes from <code>scripts/bench.py</code>; the raw results are linked per run. On your own machine
(<a href="https://github.com/radiusward/radiusward-server/blob/main/docs/testing/benchmarks.md">details</a>,
<a href="https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0066-benchmarks.md">ADR 0066</a>):</p>
<pre>./mvnw -q install -DskipTests &amp;&amp; docker build -f deploy/docker/Dockerfile -t radiusward:dev .
scripts/bench.py                                   # the compose stack on this machine
scripts/bench-aws.sh --profile small --region &lt;r&gt;  # on Amazon ECS, generators on their own instances</pre>
</section>
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
    # dedicated machines first, then the newest
    ordered = sorted(latest.values(), key=lambda r: (not r["environment"].get("shared_host"),
                                                     r["environment"].get("date", "")), reverse=True)
    sections = "".join(run_section(r) for r in ordered)
    newest = featured(runs)
    description = "Throughput, latency and failover of radiusward, an open-source replicated RADIUS server: " + "; ".join(
        f"{title.lower()} {ceiling_text(newest['workloads'][key])}" for key, title, _ in WORKLOADS
        if newest.get("workloads", {}).get(key)) + f" ({env_label(newest['environment'])})."
    page = PAGE.format(sections=sections, trend=trend_section(runs), description=esc(description))
    # wide tables scroll inside their box instead of widening the page on a phone
    page = page.replace("<table>", '<div class="scroll"><table>').replace("</table>", "</table></div>")
    open(os.path.join(bench_dir, "index.html"), "w").write(page)
    summary = {"where": newest["environment"].get("where"), "date": newest["environment"].get("date"),
               "commit": newest["environment"].get("commit"), "environment": env_label(newest["environment"]),
               "ceilings": {k: newest.get("workloads", {}).get(k, {}).get("ceiling_rps") for k, _, _ in WORKLOADS},
               # "≥" on the landing page and the badge: a lower bound, for whichever reason
               "load_limited": {k: lower_bound(newest.get("workloads", {}).get(k, {})) for k, _, _ in WORKLOADS},
               "failover_lost": bool(newest["failover"].get("problems")) if newest.get("failover") else None,
               "runs": len(runs)}
    json.dump(summary, open(os.path.join(bench_dir, "latest.json"), "w"))
    os.makedirs(os.path.join(site, "badges"), exist_ok=True)
    acct = summary["ceilings"].get("accounting")
    json.dump({"schemaVersion": 1, "label": "benchmark",
               "message": (f"accounting {'≥ ' if summary['load_limited'].get('accounting') else ''}{acct:,.0f}/s "
                           f"({summary['where']})") if acct else "no result",
               "color": "blue"}, open(os.path.join(site, "badges", "bench.json"), "w"))
    print(f"benchmarks: {len(runs)} run(s), latest {summary['where']} {summary['date']}: {summary['ceilings']}")


if __name__ == "__main__":
    main()
