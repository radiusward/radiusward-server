/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common;

import java.util.List;
import java.util.concurrent.TimeUnit;
import org.agrona.concurrent.BackoffIdleStrategy;
import org.agrona.concurrent.BusySpinIdleStrategy;
import org.agrona.concurrent.IdleStrategy;
import org.agrona.concurrent.SleepingMillisIdleStrategy;

/**
 * Resource profiles (ADR 0004). {@link #SMALL} is the default and fits a cluster node in 1 GiB.
 *
 * @param termLength Aeron term length for UDP channels (log, ingress, egress, replication)
 * @param ipcTermLength term length for IPC channels (service log replay, snapshots)
 * @param threadingMode Aeron media driver threading mode name
 * @param loggingRingSize Log4j2 async logger ring buffer slots (power of two)
 * @param maxSessions session store capacity per cluster
 * @param pendingRequests in-flight requests per gateway
 */
public enum Profile {
    SMALL(2 << 20, 2 << 20, "SHARED", 8192, 2_000_000, 16_384),
    STANDARD(8 << 20, 8 << 20, "SHARED_NETWORK", 65_536, 5_000_000, 65_536),
    LARGE(16 << 20, 16 << 20, "DEDICATED", 262_144, 20_000_000, 262_144);

    private final int termLength;
    private final int ipcTermLength;
    private final String threadingMode;
    private final int loggingRingSize;
    private final int maxSessions;
    private final int pendingRequests;

    Profile(
            int termLength,
            int ipcTermLength,
            String threadingMode,
            int loggingRingSize,
            int maxSessions,
            int pendingRequests) {
        this.termLength = termLength;
        this.ipcTermLength = ipcTermLength;
        this.threadingMode = threadingMode;
        this.loggingRingSize = loggingRingSize;
        this.maxSessions = maxSessions;
        this.pendingRequests = pendingRequests;
    }

    public int termLength() {
        return termLength;
    }

    public int ipcTermLength() {
        return ipcTermLength;
    }

    public String threadingMode() {
        return threadingMode;
    }

    public int loggingRingSize() {
        return loggingRingSize;
    }

    public int maxSessions() {
        return maxSessions;
    }

    public int pendingRequests() {
        return pendingRequests;
    }

    /** Idle strategies by name, for {@code gateway.idle.strategy}. */
    public static final List<String> IDLE_STRATEGIES =
            List.of("sleep-1ms", "backoff-1ms", "backoff-100us", "busy-spin");

    /**
     * Name of the default idle strategy: backoff parking at most 100 µs in small/standard (measured in Phase 2:
     * p50 2.7 → 1.6 ms at 2k requests/s against a 1 ms sleep, < 1 % more idle CPU), busy-spin only in large.
     */
    public String idleStrategyName() {
        return switch (this) {
            case SMALL, STANDARD -> "backoff-100us";
            case LARGE -> "busy-spin";
        };
    }

    public IdleStrategy idleStrategy() {
        return idleStrategy(idleStrategyName());
    }

    /** A new instance (idle strategies keep state, so every agent runner needs its own). */
    public static IdleStrategy idleStrategy(String name) {
        return switch (name) {
            case "sleep-1ms" -> new SleepingMillisIdleStrategy(1);
            case "backoff-1ms" ->
                new BackoffIdleStrategy(10, 20, TimeUnit.MICROSECONDS.toNanos(1), TimeUnit.MILLISECONDS.toNanos(1));
            case "backoff-100us" ->
                new BackoffIdleStrategy(10, 20, TimeUnit.MICROSECONDS.toNanos(1), TimeUnit.MICROSECONDS.toNanos(100));
            case "busy-spin" -> new BusySpinIdleStrategy();
            default ->
                throw new IllegalArgumentException("unknown idle strategy " + name + "; known: " + IDLE_STRATEGIES);
        };
    }

    /** Channel parameter fragment setting the UDP term length, e.g. {@code term-length=2m}. */
    public String termLengthParam() {
        return "term-length=" + (termLength >> 20) + "m";
    }

    public String ipcTermLengthParam() {
        return "term-length=" + (ipcTermLength >> 20) + "m";
    }
}
