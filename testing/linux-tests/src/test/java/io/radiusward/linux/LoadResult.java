/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The summary line of {@code radclient load}. */
record LoadResult(long sent, long acked, long failed, long retransmissions, double p50Ms, double p99Ms, double maxMs) {

    private static final Pattern SUMMARY = Pattern.compile("load: sent (\\d+), acked (\\d+), failed (\\d+), "
            + "retransmissions (\\d+) in .*; latency p50 ([\\d.]+) ms, p99 ([\\d.]+) ms, max ([\\d.]+) ms");

    static LoadResult parse(String output) {
        Matcher m = SUMMARY.matcher(output);
        if (!m.find()) {
            throw new IllegalStateException("no load summary in: " + output);
        }
        return new LoadResult(
                Long.parseLong(m.group(1)),
                Long.parseLong(m.group(2)),
                Long.parseLong(m.group(3)),
                Long.parseLong(m.group(4)),
                Double.parseDouble(m.group(5)),
                Double.parseDouble(m.group(6)),
                Double.parseDouble(m.group(7)));
    }
}
