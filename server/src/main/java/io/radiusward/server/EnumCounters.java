/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.common.management.PrometheusWriter;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLongArray;

/**
 * One counter per value of an enum, safe to bump from any thread without allocating, written to {@code /metrics} as
 * one sample per value labelled {@code result="<value in lower case>"}.
 */
final class EnumCounters<E extends Enum<E>> {

    private final E[] values;
    private final String[] labels;
    private final AtomicLongArray counts;

    EnumCounters(Class<E> type) {
        this.values = type.getEnumConstants();
        this.labels = new String[values.length];
        for (E v : values) {
            labels[v.ordinal()] = v.name().toLowerCase(Locale.ROOT);
        }
        this.counts = new AtomicLongArray(values.length);
    }

    void increment(E counter) {
        counts.incrementAndGet(counter.ordinal());
    }

    void add(E counter, long n) {
        counts.addAndGet(counter.ordinal(), n);
    }

    long get(E counter) {
        return counts.get(counter.ordinal());
    }

    /** The samples of a counter family the caller has started, each with {@code server} and {@code result}. */
    void write(PrometheusWriter w, String radiusServer) {
        for (E v : values) {
            w.sample(counts.get(v.ordinal()), "server", radiusServer, "result", labels[v.ordinal()]);
        }
    }
}
