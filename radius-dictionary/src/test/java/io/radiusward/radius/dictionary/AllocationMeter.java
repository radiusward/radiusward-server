/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.lang.management.ManagementFactory;

/** Bytes allocated by the current thread, via the HotSpot thread MX bean. */
final class AllocationMeter {

    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    private AllocationMeter() {}

    static long allocatedBytes() {
        return THREADS.getCurrentThreadAllocatedBytes();
    }
}
