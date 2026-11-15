/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import java.time.Duration;
import java.util.function.BooleanSupplier;

/** Waiting in tests for something to become true, instead of a fixed sleep. */
public final class Await {

    private Await() {}

    /** Polls {@code condition} every 50 ms; fails with {@code what} when it is still false after {@code timeout}. */
    public static void until(Duration timeout, String what, BooleanSupplier condition) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out waiting for: " + what);
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted waiting for: " + what);
            }
        }
    }
}
