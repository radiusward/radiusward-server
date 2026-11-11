/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.management;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryUsage;

/** JVM metrics every component exposes on {@code /metrics}. */
public final class JvmMetrics {

    private JvmMetrics() {}

    public static void write(PrometheusWriter w) {
        MemoryUsage heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        MemoryUsage nonHeap = ManagementFactory.getMemoryMXBean().getNonHeapMemoryUsage();
        w.gauge("radiusward_jvm_memory_used_bytes", "JVM memory in use")
                .sample(heap.getUsed(), "area", "heap")
                .sample(nonHeap.getUsed(), "area", "nonheap");
        w.gauge("radiusward_jvm_memory_committed_bytes", "JVM memory committed")
                .sample(heap.getCommitted(), "area", "heap")
                .sample(nonHeap.getCommitted(), "area", "nonheap");
        w.gauge("radiusward_jvm_memory_max_bytes", "JVM maximum heap").sample(heap.getMax(), "area", "heap");
        w.counter("radiusward_jvm_gc_collections_total", "Garbage collections");
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            w.sample(Math.max(0, gc.getCollectionCount()), "gc", gc.getName());
        }
        w.counter("radiusward_jvm_gc_pause_seconds_total", "Time spent in garbage collection");
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            w.sample(Math.max(0, gc.getCollectionTime()) / 1000.0, "gc", gc.getName());
        }
        w.gauge("radiusward_jvm_buffer_used_bytes", "Memory of NIO buffer pools: direct (sessions, Aeron) and mapped");
        for (java.lang.management.BufferPoolMXBean pool :
                ManagementFactory.getPlatformMXBeans(java.lang.management.BufferPoolMXBean.class)) {
            w.sample(Math.max(0, pool.getMemoryUsed()), "pool", pool.getName());
        }
        w.gauge("radiusward_jvm_threads", "Live threads")
                .sample(ManagementFactory.getThreadMXBean().getThreadCount());
        w.gauge("radiusward_process_uptime_seconds", "Time since the JVM started")
                .sample(ManagementFactory.getRuntimeMXBean().getUptime() / 1000.0);
    }
}
