#!/bin/sh
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Copies the alert rules and Grafana dashboards of deploy/monitoring into the Helm chart's files/ (Helm can only
# read files inside the chart). MonitoringConfigTest fails while the two differ.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
chart="$root/deploy/helm/radiusward/files"
cp "$root/deploy/monitoring/alerts.yml" "$chart/alerts.yml"
rm -f "$chart"/dashboards/*.json
cp "$root"/deploy/monitoring/grafana/dashboards/*.json "$chart/dashboards/"
echo "copied alerts.yml and $(ls "$chart"/dashboards | wc -l | tr -d ' ') dashboards into $chart"
