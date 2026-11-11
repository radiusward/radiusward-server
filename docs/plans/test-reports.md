# Plan: published test reports (Allure 3 on GitHub Pages)

Status: **planned** (2026-11-11). ADR [0064](../adr/0064-test-reports.md). Work packages R1–R3.

## Goal

Anyone can see, from a button on the README, which behaviour the slower test suites verified on the latest `main`
and last night: which tests ran, which failed and why, how long they took, and how that changed over the last runs.
Unit tests and coverage stay with SonarCloud; these reports are about integration, end-to-end, fault-injection and
Kubernetes tests, the ones whose results today live only in workflow logs and artifacts.

## Decisions (2026-11-11)

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Report tool | **Allure Report 3** (npm `allure`, pinned, currently 3.33.0), the `awesome` report | current line; history, flaky detection and quality gates built in; Allure 2's Pages action is a community one |
| 2 | History | `historyPath` per report: a `history.jsonl` kept next to the report on `gh-pages`, restored before and written back after each generation, `historyLimit: 30` | trends and flaky detection without Allure's storage service; the Pages guide's "no history" applies only to its minimal example |
| 3 | First input | the **JUnit XML** Maven already writes (Allure 3's `junitxml` reader); `allure-jupiter` (3.x) only in R2 | a useful report without touching a test |
| 4 | Reports | four, each with its own history: **integration**, **end-to-end**, **fault injection** (Linux, nightly), **Kubernetes** (nightly) | a green push never hides last night's red nightly suite |
| 5 | When | integration and end-to-end on every push to `main`; the nightly ones after their scheduled or manual run on `main` | the README always shows the current `main` |
| 6 | Where | **GitHub Pages** from a `gh-pages` branch, one folder per report and a landing page | public like the repository, no extra service |
| 7 | Who publishes | one workflow, `reports.yml`, on `workflow_run` of `ci`, `linux-tests` and `k8s-tests`; serialized; pull requests never publish | the test jobs need no write permission; a privileged job that only reads data |
| 8 | README | a shields.io endpoint badge per report (count and status), each linking to its report, plus a "test reports" link to the landing page | live numbers without a badge service of our own |
| 9 | PR feedback | `allure-framework/allure-action` summaries and a quality-gate check on pull requests (R3) | Dependabot and outside pull requests get a readable result |

## Design

### Results from the test workflows

The test jobs upload their results on **every** run (today only on failure), as data only:

| Report | Job | Artifact | Files |
|---|---|---|---|
| integration | `ci.yml` › verify | `results-integration` | `**/target/failsafe-reports/TEST-*.xml` (Surefire's unit-test XML is left out) |
| end-to-end | `ci.yml` › e2e | `results-e2e` | `testing/e2e-tests/target/failsafe-reports/TEST-*.xml` |
| fault injection | `linux-tests.yml` | `results-linux` | `testing/linux-tests/target/failsafe-reports/TEST-*.xml`, container logs |
| Kubernetes | `k8s-tests.yml` | `results-k8s` | `testing/k8s-tests/target/junit.xml` (one test case per scenario, written by `scripts/k8s-tests.sh`), pod logs |

The existing report artifacts stay as they are for runs that crash before writing XML.

### Publishing (`reports.yml`)

```text
on: workflow_run [ci, linux-tests, k8s-tests] completed, branch main, event push | schedule | workflow_dispatch
permissions: contents: write (gh-pages), actions: read (artifacts)
concurrency: gh-pages (queued, never cancelled)

1. check out gh-pages (create it on the first run)
2. download the triggering run's results-* artifacts (data only; nothing from them is executed)
3. per report found:
     restore <report>/history.jsonl
     npx allure@<pinned> generate <xml> -o <report>/  (config: .github/allure/allurerc.mjs, report name, history,
       variables: commit, branch, run link, Java version, date)
     write badges/<report>.json (shields endpoint: "412 passed" / "3 failed", colour)
4. regenerate index.html from every report's summary.json (status, counts, date, commit, links)
5. commit to gh-pages and push
```

A report that has no results in the triggering run (a job that died before writing XML) keeps its previous content and
gets a "no results" note on the landing page rather than an empty report.

### Site layout

```text
https://radiusward.github.io/radiusward-server/
  index.html                       landing page: four cards with status, counts, date, commit
  integration/  e2e/  linux/  k8s/ the Allure report and its history.jsonl
  badges/<report>.json             shields.io endpoint data
```

Only the latest HTML of each report is kept; history is the JSONL (≤ 30 runs), so `gh-pages` stays small.

### README

```markdown
[![Integration tests](https://img.shields.io/endpoint?url=https://radiusward.github.io/radiusward-server/badges/integration.json)](https://radiusward.github.io/radiusward-server/integration/)
```

and the same for end-to-end, fault injection and Kubernetes, next to the CI, CodeQL and Sonar badges.

### Richer reports (R2)

`allure-jupiter` as a **test-scope** dependency in a Failsafe-only profile (no effect on what ships), writing
`allure-results` next to the XML; the report then reads both.

- **Grouping**: epics and features by area (Accounting, Authentication, EAP, Cluster, Export, Kubernetes, Fault
  injection), links to the ADR a test proves (e.g. `ClusterSeedIT` → ADR 0063).
- **Steps** from the shared helpers, so most tests get them without edits: `LocalCluster` (start members and
  gateways, stop/kill/seed a member, snapshot), `ContainerCluster` (power loss, partition, full disk, kill), the
  radclient load (sent/acked/retransmissions as step parameters).
- **Attachments**, on failure always and on success where small: member and gateway logs, container logs, the load
  summary, a `/metrics` snapshot; collected without masking the original failure.
- **Run details** on every report: commit, run link, Java version, profile, Kubernetes version.

### Pull requests (R3)

On pull requests the integration and end-to-end reports are generated as an artifact (never published) and
`allure-framework/allure-action` posts a summary comment (new, flaky, retried) with a quality-gate check
(`pull-requests: write`, `checks: write`; read-only on forks).

## Work packages

| # | Package | Content | Size |
|---|---|---|---|
| R1 | Reports and badges | results uploaded on every run, `junit.xml` from `k8s-tests.sh`, `reports.yml`, Allure config, landing page, `gh-pages` and Pages enabled, README badges, `docs/testing/strategy.md` | M |
| R2 | Richer reports | `allure-jupiter` profile, epics/features/ADR links, steps in `LocalCluster`/`ContainerCluster`/load, log attachments | M |
| R3 | Pull requests | report artifact and `allure-action` summary and check on pull requests | S |

## Risks

- **JUnit XML fidelity**: the `junitxml` reader gives names, durations, failures and stack traces but no steps; R1
  starts by generating one report locally from real Failsafe XML to see exactly what it shows.
- **Allure 3 moves fast**: the CLI version is pinned and updated deliberately; Dependabot does not see `npx` versions,
  so the pin lives in one place (`reports.yml`).
- **Public logs**: reports and attachments are public; tests use throwaway secrets only, and R2 attaches logs that the
  server already writes without secrets.
- **Pages limits**: a build per push to `main` plus two nightly ones stays far below GitHub's limits.
