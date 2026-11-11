#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Builds the published test reports (docs/plans/test-reports.md, ADR 0064): for every suite whose results are in
# <results>, an Allure 3 report with its history in <site>/<suite>/, shields.io badge data in <site>/badges/ and the
# landing page <site>/index.html. Suites without results keep their previous report. Used by reports.yml; locally:
#
#   scripts/test-reports.sh <results> <site>        # <results>/results-integration/**/TEST-*.xml, ... → <site>
#   (cd <site> && python3 -m http.server)           # then open http://localhost:8000
#
# Environment: REPORT_COMMIT, REPORT_BRANCH, REPORT_RUN_URL (shown in the report), ALLURE (CLI version).
set -euo pipefail

results=$(cd "$1" && pwd)
mkdir -p "$2"
site=$(cd "$2" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
allure_version=${ALLURE:-3.33.0}

# suite id | title | what it runs
suites=(
  "integration|Integration tests|Failsafe *IT of every module on each push to main: gateways, cluster members and stores together in one JVM"
  "e2e|End-to-end tests|separate radiusward processes on each push to main: failover, retransmissions, rolling upgrade"
  "linux|Fault injection|nightly on Linux in containers: power loss with LazyFS, partitions, full disk, overload, PostgreSQL outage"
  "k8s|Kubernetes|nightly on kind with the Helm chart under load: leader killed, members and gateways rolled, a volume replaced"
)

generate() {
  local id=$1 title=$2 tmp
  local xml
  xml=$(find "$results/results-$id" -type f -name '*.xml' 2>/dev/null | grep -E '/(TEST-[^/]*|junit)\.xml$' || true)
  if [[ -z "$xml" ]]; then
    return
  fi
  tmp=$(mktemp -d)
  mkdir "$tmp/xml"
  while IFS= read -r f; do cp "$f" "$tmp/xml/"; done <<<"$xml"
  [[ -f "$site/$id/history.jsonl" ]] && cp "$site/$id/history.jsonl" "$tmp/history.jsonl"
  echo "$id: $(ls "$tmp/xml" | wc -l | tr -d ' ') result files"
  REPORT_NAME="radiusward · $title" REPORT_OUTPUT="$tmp/report" REPORT_HISTORY="$tmp/history.jsonl" \
    npx -y "allure@$allure_version" generate "$tmp/xml" -c "$root/.github/allure/allurerc.mjs" >/dev/null
  cp "$tmp/history.jsonl" "$tmp/report/history.jsonl"
  python3 - "$tmp/report" <<'EOF'
import json, os, sys
from datetime import datetime, timezone
out = sys.argv[1]
json.dump({
    "commit": os.environ.get("REPORT_COMMIT", "local"),
    "branch": os.environ.get("REPORT_BRANCH", "local"),
    "run": os.environ.get("REPORT_RUN_URL", ""),
    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
}, open(os.path.join(out, "meta.json"), "w"))
EOF
  rm -rf "${site:?}/$id"
  mv "$tmp/report" "$site/$id"
  rm -rf "$tmp"
}

for s in "${suites[@]}"; do
  IFS='|' read -r id title _ <<<"$s"
  generate "$id" "$title"
done

# badges (shields.io endpoint format) and the landing page, from every report that exists
python3 - "$site" "${suites[@]}" <<'EOF'
import html, json, os, sys

site, suites = sys.argv[1], [s.split("|", 2) for s in sys.argv[2:]]
os.makedirs(os.path.join(site, "badges"), exist_ok=True)
cards = []
for sid, title, what in suites:
    summary_file = os.path.join(site, sid, "summary.json")
    if not os.path.exists(summary_file):
        cards.append((sid, title, what, None, None))
        continue
    summary = json.load(open(summary_file))
    meta_file = os.path.join(site, sid, "meta.json")
    meta = json.load(open(meta_file)) if os.path.exists(meta_file) else {}
    s = summary.get("stats", {})
    bad = s.get("failed", 0) + s.get("broken", 0)
    passed = s.get("passed", 0)
    message = f"{bad} failed, {passed} passed" if bad else f"{passed} passed"
    if s.get("skipped"):
        message += f", {s['skipped']} skipped"
    json.dump({"schemaVersion": 1, "label": title.lower(), "message": message,
               "color": "red" if bad else ("brightgreen" if passed else "lightgrey")},
              open(os.path.join(site, "badges", f"{sid}.json"), "w"))
    cards.append((sid, title, what, (bad, passed, s.get("skipped", 0), s.get("total", 0)), meta))

def card(sid, title, what, stats, meta):
    if stats is None:
        return f"""<article class="card none"><h2>{html.escape(title)}</h2><p class="what">{html.escape(what)}</p>
<p class="status">no results yet</p></article>"""
    bad, passed, skipped, total = stats
    state = "fail" if bad else "pass"
    commit = meta.get("commit", "")
    run = meta.get("run", "")
    commit_html = (f'<a href="https://github.com/radiusward/radiusward-server/commit/{html.escape(commit)}">'
                   f'{html.escape(commit[:7])}</a>') if len(commit) >= 7 else html.escape(commit)
    run_html = f' · <a href="{html.escape(run)}">workflow run</a>' if run else ""
    return f"""<article class="card {state}">
<h2><a href="{sid}/">{html.escape(title)}</a></h2>
<p class="what">{html.escape(what)}</p>
<p class="status">{"✗ " + str(bad) + " failed" if bad else "✓ all passed"}</p>
<p class="counts">{passed} passed · {bad} failed · {skipped} skipped · {total} total</p>
<p class="meta">{html.escape(meta.get("date", ""))} · commit {commit_html}{run_html}</p>
<p><a class="open" href="{sid}/">Open the report →</a></p>
</article>"""

page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>radiusward test reports</title>
<style>
:root {{ --bg:#f6f7f9; --fg:#1d2330; --muted:#5c6577; --card:#fff; --line:#dfe3ea; --pass:#1a7f37; --fail:#cf222e; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1218; --fg:#e6e9ef; --muted:#9aa3b5; --card:#181c24;
  --line:#2a303c; --pass:#3fb950; --fail:#f85149; }} }}
* {{ box-sizing:border-box }} body {{ margin:0; background:var(--bg); color:var(--fg);
  font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif }}
main {{ max-width:960px; margin:0 auto; padding:32px 16px }} h1 {{ margin:0 0 4px; font-size:28px }}
.lead {{ color:var(--muted); margin:0 0 24px }} a {{ color:inherit }}
.grid {{ display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr)) }}
.card {{ background:var(--card); border:1px solid var(--line); border-left:6px solid var(--line); border-radius:8px;
  padding:16px 20px }} .card.pass {{ border-left-color:var(--pass) }} .card.fail {{ border-left-color:var(--fail) }}
.card h2 {{ margin:0 0 4px; font-size:20px }} .what,.meta,.counts {{ color:var(--muted); margin:4px 0; font-size:14px }}
.status {{ font-weight:600; margin:8px 0 0 }} .pass .status {{ color:var(--pass) }} .fail .status {{ color:var(--fail) }}
.open {{ font-weight:600; text-decoration:none }}
</style></head>
<body><main>
<h1>radiusward test reports</h1>
<p class="lead">What the slower suites verified on the latest <code>main</code> and last night, with history of the
last 30 runs. Unit tests and coverage: <a href="https://sonarcloud.io/project/overview?id=radiusward_radiusward-server">SonarCloud</a>.
Source: <a href="https://github.com/radiusward/radiusward-server">radiusward/radiusward-server</a>.</p>
<div class="grid">
{"".join(card(*c) for c in cards)}
</div></main></body></html>
"""
open(os.path.join(site, "index.html"), "w").write(page)
open(os.path.join(site, ".nojekyll"), "w").close()
print("landing page:", ", ".join(f"{c[0]}={'none' if c[3] is None else ('fail' if c[3][0] else 'pass')}" for c in cards))
EOF
