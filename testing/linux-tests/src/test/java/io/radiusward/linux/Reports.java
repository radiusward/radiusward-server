/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import io.qameta.allure.Allure;

/**
 * Steps and attachments for the published test reports (ADR 0064; the same as {@code io.radiusward.testing.Reports},
 * which this module does not depend on). They are recorded only with {@code -Preports},
 * which adds the Allure listener and sets {@code radiusward.reports}; otherwise a step just runs its body, so tests
 * behave the same either way. Attachments never fail a test.
 */
final class Reports {

    private static final boolean ON = Boolean.getBoolean("radiusward.reports");

    /** A step body that may throw. */
    @FunctionalInterface
    interface Body {
        void run() throws Exception;
    }

    /** A step body that returns a value and may throw. */
    @FunctionalInterface
    interface Supplier<T> {
        T get() throws Exception;
    }

    private Reports() {}

    /** Runs {@code body} as a report step named {@code name}. */
    static void step(String name, Body body) {
        if (!ON) {
            run(body);
            return;
        }
        Allure.step(name, body::run);
    }

    /** Runs {@code body} as a report step named {@code name} and returns its value. */
    static <T> T step(String name, Supplier<T> body) {
        if (!ON) {
            try {
                return body.get();
            } catch (Exception e) {
                throw sneaky(e);
            }
        }
        return Allure.step(name, body::get);
    }

    /** Attaches {@code text} to the current test or step; ignored when it cannot be attached. */
    static void attach(String name, String text) {
        if (!ON || text == null) {
            return;
        }
        try {
            Allure.addAttachment(name, "text/plain", text, ".txt");
        } catch (RuntimeException e) {
            // a diagnostic must never hide the test's own result
        }
    }

    private static void run(Body body) {
        try {
            body.run();
        } catch (Exception e) {
            throw sneaky(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <E extends Exception> RuntimeException sneaky(Exception e) throws E {
        throw (E) e; // rethrows a checked exception unchanged: callers keep their declared exceptions
    }
}
