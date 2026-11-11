// Copyright 2026 The radiusward Authors
// SPDX-License-Identifier: Apache-2.0
//
// Allure 3 configuration of the published test reports (docs/plans/test-reports.md, ADR 0064). One report per suite;
// scripts/test-reports.sh sets the values. A plain object: the config must load without the allure package installed.
const env = process.env;

export default {
  name: env.REPORT_NAME,
  output: env.REPORT_OUTPUT,
  historyPath: env.REPORT_HISTORY,
  historyLimit: 30,
  variables: {
    Commit: env.REPORT_COMMIT ?? "local",
    Branch: env.REPORT_BRANCH ?? "local",
    Workflow: env.REPORT_RUN_URL ?? "local",
    Java: "25",
  },
  plugins: {
    awesome: {
      options: {
        reportName: env.REPORT_NAME,
        singleFile: false,
        reportLanguage: "en",
      },
    },
  },
};
