/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.management.PrometheusWriter;
import java.util.concurrent.atomic.AtomicLongArray;

/**
 * Look-ups of one identity store for the metrics: how long they took, as a histogram, and what they found. Written by
 * the access workers without locks or allocation, read by {@code /metrics}.
 */
final class StoreLookups {

    /** Outcomes, in the order of their counters. */
    static final String[] RESULTS = {"found", "not_found", "unavailable"};

    static final int FOUND = 0;
    static final int NOT_FOUND = 1;
    static final int UNAVAILABLE = 2;

    /** Upper bounds in seconds: a local file answers in microseconds, a remote directory in tens of milliseconds. */
    static final double[] BOUNDS = {0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5};

    private final AtomicLongArray buckets = new AtomicLongArray(BOUNDS.length + 1);
    private final AtomicLongArray outcomes = new AtomicLongArray(RESULTS.length);
    private final java.util.concurrent.atomic.AtomicLong nanos = new java.util.concurrent.atomic.AtomicLong();

    void record(long elapsedNanos, int result) {
        double seconds = elapsedNanos / 1e9;
        int b = 0;
        while (b < BOUNDS.length && seconds > BOUNDS[b]) {
            b++;
        }
        buckets.getAndIncrement(b);
        nanos.addAndGet(elapsedNanos);
        outcomes.getAndIncrement(result);
    }

    long result(int result) {
        return outcomes.get(result);
    }

    /** Cumulative counts per bound and +Inf, as Prometheus wants them. */
    long[] cumulative() {
        long[] out = new long[BOUNDS.length + 1];
        long sum = 0;
        for (int i = 0; i < out.length; i++) {
            sum += buckets.get(i);
            out[i] = sum;
        }
        return out;
    }

    double seconds() {
        return nanos.get() / 1e9;
    }

    /** Both families for every store, in name order. */
    static void write(PrometheusWriter w, String gateway, java.util.SortedMap<String, StoreLookups> stores) {
        if (stores.isEmpty()) {
            return;
        }
        w.counter("radiusward_gateway_store_lookups_total", "Identity store look-ups by result (cache hits excluded)");
        stores.forEach((name, s) -> {
            for (int r = 0; r < RESULTS.length; r++) {
                w.sample(s.result(r), "gateway", gateway, "store", name, "result", RESULTS[r]);
            }
        });
        w.family("radiusward_gateway_store_lookup_seconds", "histogram", "How long identity store look-ups took");
        stores.forEach(
                (name, s) -> w.histogram(BOUNDS, s.cumulative(), s.seconds(), "gateway", gateway, "store", name));
    }
}
