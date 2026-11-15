/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import org.agrona.collections.ObjectHashSet;
import org.apache.logging.log4j.Logger;

/**
 * Warnings about configuration or stored data that would otherwise repeat for every request: each key is logged
 * once (a user's broken secret, a pattern that does not compile).
 */
final class OnceLogger {

    private final Logger log;
    private final ObjectHashSet<String> warned = new ObjectHashSet<>();

    OnceLogger(Logger log) {
        this.log = log;
    }

    private boolean first(String key) {
        synchronized (warned) { // rare: only for problems that are logged once
            return warned.add(key);
        }
    }

    void warn(String key, String message, Object detail) {
        if (first(key)) {
            log.warn(message, detail);
        }
    }

    void warn(String key, String message, Object a, Object b) {
        if (first(key)) {
            log.warn(message, a, b);
        }
    }
}
