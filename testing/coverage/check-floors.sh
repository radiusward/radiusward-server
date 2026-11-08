#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Checks the aggregate line coverage of each module (-Pcoverage) against floors.properties.
# usage: check-floors.sh <jacoco.csv> <floors.properties>
set -euo pipefail

csv=${1:?jacoco.csv}
floors=${2:?floors.properties}

awk -F, '
    FNR == NR {
        if ($0 ~ /^[[:space:]]*(#|$)/) next
        split($0, kv, "=")
        gsub(/[[:space:]]/, "", kv[1]); gsub(/[[:space:]]/, "", kv[2])
        floor[kv[1]] = kv[2]
        next
    }
    FNR == 1 { next }
    {
        module = $1; sub(/.*\//, "", module)
        missed[module] += $8; covered[module] += $9
        allMissed += $8; allCovered += $9
    }
    END {
        failed = 0
        for (m in floor) {
            if (m == "total") { lines = allMissed + allCovered; ratio = lines ? allCovered / lines : 0 }
            else if (!((m in missed) || (m in covered))) { printf "coverage: no data for module %s\n", m; failed = 1; continue }
            else { lines = missed[m] + covered[m]; ratio = lines ? covered[m] / lines : 0 }
            verdict = ratio + 1e-9 >= floor[m] ? "ok" : "BELOW FLOOR"
            if (verdict != "ok") failed = 1
            printf "coverage: %-18s lines %5.1f %%  floor %5.1f %%  %s\n", m, ratio * 100, floor[m] * 100, verdict
        }
        exit failed
    }
' "$floors" "$csv"
