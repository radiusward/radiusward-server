/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.util.concurrent.atomic.AtomicLongArray;

/** Counters of the Access-Request path; written by the auth agent and the workers, read by management. */
public final class AuthStats {

    public enum Counter {
        RECEIVED,
        MALFORMED,
        NOT_ACCESS_REQUEST,
        /** Status-Server (RFC 5997) answered with an Access-Accept */
        STATUS_SERVER,
        UNKNOWN_NAS,
        /** the NAS entry requires Message-Authenticator (default), or the request carries EAP, and it was absent */
        MESSAGE_AUTHENTICATOR_MISSING,
        MESSAGE_AUTHENTICATOR_FAILED,
        /** a retransmission answered with the cached reply */
        CACHE_HITS,
        /** a retransmission of a request still being decided: dropped */
        RETRANSMIT_IN_FLIGHT,
        /** sent on to a home server of a proxied realm (ADR 0037) */
        PROXIED,
        /** no free slot or the work queue full: dropped, the NAS retransmits */
        BUSY,
        ACCEPTED,
        REJECTED,
        CHALLENGED,
        /** the handler chose not to answer (e.g. the identity store is unreachable) */
        DROPPED,
        /** the handler threw: dropped */
        HANDLER_ERRORS,
        RESPONSES_SENT,
        SEND_FAILED
    }

    private static final Counter[] COUNTERS = Counter.values();
    private final AtomicLongArray values = new AtomicLongArray(COUNTERS.length);
    private volatile boolean bound;
    private volatile int inFlight;
    private volatile int cached;

    void increment(Counter counter) {
        values.getAndIncrement(counter.ordinal());
    }

    public long get(Counter counter) {
        return values.get(counter.ordinal());
    }

    public static Counter[] counters() {
        return COUNTERS;
    }

    void bound(boolean value) {
        bound = value;
    }

    /** Whether the Access-Request socket is bound. */
    public boolean bound() {
        return bound;
    }

    void inFlight(int value) {
        inFlight = value;
    }

    /** Requests handed to the workers and not answered yet. */
    public int inFlight() {
        return inFlight;
    }

    void cached(int value) {
        cached = value;
    }

    /** Replies in the reply cache. */
    public int cached() {
        return cached;
    }
}
