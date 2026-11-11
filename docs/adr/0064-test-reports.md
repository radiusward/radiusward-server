# ADR 0064: Published test reports with Allure 3 on GitHub Pages

Status: Accepted (2026-11-11). Plan: [plans/test-reports.md](../plans/test-reports.md).

## Context
The integration, end-to-end, fault-injection and Kubernetes suites prove the properties radiusward promises (an
acknowledged record survives a member's loss, failover without retransmissions, a replaced volume rejoins), but their
results live in workflow logs and in artifacts uploaded only on failure. SonarCloud shows coverage and code quality,
not which behaviour was verified. The README should link to a readable report of the latest `main` and the latest
nightly runs.

## Decision
- **Allure Report 3** generates one report per suite — integration, end-to-end, fault injection, Kubernetes — each
  with its own history (`historyPath`, a `history.jsonl` kept with the report, the last 30 runs), so trends and flaky
  tests show without Allure's storage service, and a green push never hides a red nightly run.
- The first input is the **JUnit XML** Maven and the Kubernetes test script already write (Allure 3's `junitxml`
  reader); `allure-jupiter` (test scope, Failsafe profile) adds steps, ADR links and log attachments later.
- One workflow, `reports.yml`, triggered by the test workflows' completion on `main`, generates the reports, writes
  shields.io badge data and a landing page, and pushes to the `gh-pages` branch served by **GitHub Pages**. It is the
  only workflow that writes there, runs one at a time, executes nothing from the artifacts it downloads, and never
  publishes pull requests. Test jobs upload their results on every run.
- The README gets one badge per report linking to it. Pull requests later get `allure-action` summaries and a
  quality-gate check, as artifacts only.

## Consequences
- Reports and their attachments are public; tests keep using throwaway secrets.
- A Node-based tool (npm `allure`, pinned) runs in CI; nothing changes in what radiusward ships.
- Unit tests and coverage stay with SonarCloud.
