/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common;

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

    /** Idle strategy for agents: low CPU in small/standard, busy-spin only in large. */
    public IdleStrategy idleStrategy() {
        return switch (this) {
            case SMALL -> new SleepingMillisIdleStrategy(1);
            case STANDARD ->
                new BackoffIdleStrategy(10, 20, TimeUnit.MICROSECONDS.toNanos(1), TimeUnit.MILLISECONDS.toNanos(1));
            case LARGE -> new BusySpinIdleStrategy();
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
