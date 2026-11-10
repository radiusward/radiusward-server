/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.logging;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.management.ManagementFactory;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.async.AsyncLoggerContextSelector;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.util.Unbox;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Proves the logging contract (ADR 0013) with the real Log4j2 configuration from this module: all loggers are
 * async, parameterized logging does not allocate on the calling thread, and a full ring buffer drops events
 * instead of blocking. Runs under Failsafe with the small-profile ring size (8192 slots).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class NonBlockingLoggingIT {

    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    /** Appender that can be made to block, simulating a stuck disk or console. */
    static final class GateAppender extends AbstractAppender {
        volatile CountDownLatch gate = new CountDownLatch(0);
        volatile long received;

        GateAppender() {
            super("gate", null, null, true, Property.EMPTY_ARRAY);
        }

        @Override
        public void append(LogEvent event) {
            received++;
            try {
                gate.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static final GateAppender APPENDER = install();
    private static final Logger LOG = LogManager.getLogger("io.radiusward.test.hotpath");

    private static GateAppender install() {
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = context.getConfiguration();
        GateAppender appender = new GateAppender();
        appender.start();
        configuration.addAppender(appender);
        LoggerConfig loggerConfig = LoggerConfig.newBuilder()
                .setLoggerName("io.radiusward.test")
                .setLevel(org.apache.logging.log4j.Level.INFO)
                .setAdditivity(false)
                .setIncludeLocation("false") // as in log4j2.xml: location capture walks the stack and allocates
                .setConfig(configuration)
                .build();
        loggerConfig.addAppender(appender, null, null);
        configuration.addLogger("io.radiusward.test", loggerConfig);
        context.updateLoggers();
        return appender;
    }

    @Test
    @Order(1)
    void allLoggersAreAsync() {
        assertThat(AsyncLoggerContextSelector.isSelected()).isTrue();
        assertThat(LOG.getClass().getSimpleName()).isEqualTo("AsyncLogger");
    }

    @Test
    @Order(2)
    void parameterizedLoggingDoesNotAllocate() throws InterruptedException {
        for (int i = 0; i < 50_000; i++) { // > several ring cycles: each slot allocates its StringBuilder once
            LOG.info("nas {} dropped packet {} reason {}", Unbox.box(i & 7), Unbox.box(i), Unbox.box(3L));
        }
        // steady state: on a slow machine the JIT may still be compiling the logging path after the warm-up, and
        // interpreted code allocates what compiled code does not; the best of a few rounds is what is measured
        long allocated = Long.MAX_VALUE;
        for (int round = 0; round < 5 && allocated >= 64 * 1024; round++) {
            Thread.sleep(200); // let the background thread drain
            long before = THREADS.getCurrentThreadAllocatedBytes();
            for (int i = 0; i < 100_000; i++) {
                LOG.info("nas {} dropped packet {} reason {}", Unbox.box(i & 7), Unbox.box(i), Unbox.box(3L));
            }
            allocated = Math.min(allocated, THREADS.getCurrentThreadAllocatedBytes() - before);
        }
        assertThat(allocated).as("bytes allocated by 100k log calls").isLessThan(64 * 1024);
    }

    @Test
    @Order(3)
    void fullRingBufferDropsInsteadOfBlocking() {
        CountDownLatch gate = new CountDownLatch(1);
        APPENDER.gate = gate;
        try {
            long droppedBefore = NonBlockingQueueFullPolicy.dropped();
            long start = System.nanoTime();
            for (int i = 0; i < 20_000; i++) {
                LOG.error("burst {}", Unbox.box(i)); // ERROR: Log4j's own Discard policy would block here
            }
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertThat(elapsedMs).as("20k log calls with a stuck appender").isLessThan(2_000);
            // the ring holds 8192 events (one more is in the stuck appender); everything beyond is dropped
            assertThat(NonBlockingQueueFullPolicy.dropped() - droppedBefore).isGreaterThan(20_000 - 8192 - 2);
        } finally {
            gate.countDown();
            APPENDER.gate = new CountDownLatch(0);
        }
    }
}
