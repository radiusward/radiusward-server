/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import io.radiusward.export.AccountingSink;
import io.radiusward.export.Batch;
import io.radiusward.export.FencedException;
import io.radiusward.export.SinkContext;
import io.radiusward.export.SinkProvider;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A sink for exporter tests ({@code type = faulty}) that keeps its position in memory and refuses writes on demand: as
 * fenced by a newer epoch, or failed. One instance per test JVM at a time; {@link #reset()} before each test.
 */
public final class FaultySink implements AccountingSink {

    static final AtomicInteger fenceNext = new AtomicInteger();
    static final AtomicInteger failNext = new AtomicInteger();
    static final AtomicInteger fenced = new AtomicInteger();
    static final AtomicInteger failed = new AtomicInteger();
    static final AtomicInteger opened = new AtomicInteger();
    static final AtomicInteger written = new AtomicInteger();
    static final AtomicLong position = new AtomicLong(-1);

    static void reset() {
        fenceNext.set(0);
        failNext.set(0);
        fenced.set(0);
        failed.set(0);
        opened.set(0);
        written.set(0);
        position.set(-1);
    }

    @Override
    public void open(SinkContext context) {
        opened.incrementAndGet();
    }

    @Override
    public CheckpointStyle checkpointStyle() {
        return CheckpointStyle.TRANSACTIONAL;
    }

    @Override
    public long storedPosition() {
        return position.get();
    }

    @Override
    public void write(Batch batch) throws IOException, FencedException {
        if (fenceNext.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
            fenced.incrementAndGet();
            throw new FencedException("epoch " + batch.epoch() + " < stored epoch " + (batch.epoch() + 1));
        }
        if (failNext.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
            failed.incrementAndGet();
            throw new IOException("injected write failure");
        }
        written.addAndGet(batch.events().size() + batch.sessions().size());
        position.set(batch.toPosition());
    }

    @Override
    public void close() {}

    /** Registered in {@code META-INF/services}. */
    public static final class Provider implements SinkProvider {

        @Override
        public String type() {
            return "faulty";
        }

        @Override
        public AccountingSink create() {
            return new FaultySink();
        }
    }
}
