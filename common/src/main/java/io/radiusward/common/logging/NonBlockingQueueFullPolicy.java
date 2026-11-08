/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.logging;

import java.util.concurrent.atomic.AtomicLong;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.async.AsyncQueueFullPolicy;
import org.apache.logging.log4j.core.async.EventRoute;

/**
 * Log4j2 policy for a full async-logger ring buffer: always discard, whatever the level, and count it.
 *
 * <p>Log4j's default policy blocks the logging thread until the background thread catches up, and its
 * {@code Discard} policy still blocks for WARN and above. Either could stall an Aeron agent or the UDP
 * receive loop, so radiusward drops the event instead (ADR 0013). The count is exposed in {@code /state}.
 *
 * <p>Activated by {@code log4j2.asyncQueueFullPolicy} in {@code log4j2.component.properties}.
 */
public final class NonBlockingQueueFullPolicy implements AsyncQueueFullPolicy {

    private static final AtomicLong DROPPED = new AtomicLong();

    @Override
    public EventRoute getRoute(long backgroundThreadId, Level level) {
        DROPPED.incrementAndGet();
        return EventRoute.DISCARD;
    }

    /** Log events dropped because the ring buffer was full, since JVM start. */
    public static long dropped() {
        return DROPPED.get();
    }
}
