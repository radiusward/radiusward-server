/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.util.concurrent.atomic.AtomicLongArray;

/** Gateway counters, written by the agents with ordered stores and read by the management thread. */
public final class GatewayStats {

    public enum Counter {
        RECEIVED,
        MALFORMED,
        UNKNOWN_NAS,
        NOT_ACCOUNTING,
        AUTHENTICATOR_FAILED,
        MESSAGE_AUTHENTICATOR_FAILED,
        MISSING_SESSION_ID,
        CACHE_HITS,
        RETRANSMIT_IN_FLIGHT,
        RESUBMITTED,
        PENDING_FULL,
        RING_FULL,
        TOO_MANY_PROXY_STATES,
        SUBMITTED,
        OFFERED,
        BACK_PRESSURED,
        COMMITTED,
        DUPLICATES,
        STALE,
        REJECTED,
        TIMED_OUT,
        LATE_COMMITS,
        RESPONSES_SENT,
        SEND_FAILED,
        CLUSTER_CONNECTS,
        CLUSTER_DISCONNECTS
    }

    private static final Counter[] COUNTERS = Counter.values();

    private final AtomicLongArray values = new AtomicLongArray(COUNTERS.length + 4);
    private static final int CONNECTED = COUNTERS.length;
    private static final int BOUND = COUNTERS.length + 1;
    private static final int PENDING = COUNTERS.length + 2;
    private static final int CACHE = COUNTERS.length + 3;

    /** Single-writer increment (each counter is only touched by one agent thread). */
    void increment(Counter counter) {
        int i = counter.ordinal();
        values.setRelease(i, values.getPlain(i) + 1);
    }

    void connected(boolean connected) {
        values.setRelease(CONNECTED, connected ? 1 : 0);
    }

    void bound(boolean bound) {
        values.setRelease(BOUND, bound ? 1 : 0);
    }

    void gauges(int pending, int cacheSize) {
        values.setRelease(PENDING, pending);
        values.setRelease(CACHE, cacheSize);
    }

    public long get(Counter counter) {
        return values.getAcquire(counter.ordinal());
    }

    public boolean connected() {
        return values.getAcquire(CONNECTED) == 1;
    }

    public boolean bound() {
        return values.getAcquire(BOUND) == 1;
    }

    public long pending() {
        return values.getAcquire(PENDING);
    }

    public long cacheSize() {
        return values.getAcquire(CACHE);
    }

    static Counter[] counters() {
        return COUNTERS;
    }
}
