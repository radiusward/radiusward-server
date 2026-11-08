/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.logging;

import io.radiusward.common.Profile;

/**
 * Applies per-profile Log4j2 settings. Must run before the first logger is created, so call it as the first
 * statement of a {@code main} method whose class has no static logger.
 */
public final class Logging {

    private Logging() {}

    public static void configure(Profile profile) {
        setIfAbsent("log4j2.asyncLoggerRingBufferSize", Integer.toString(profile.loggingRingSize()));
    }

    private static void setIfAbsent(String key, String value) {
        if (System.getProperty(key) == null) {
            System.setProperty(key, value);
        }
    }
}
