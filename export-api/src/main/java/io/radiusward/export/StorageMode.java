/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

/** What a sink stores (ADR 0018). */
public enum StorageMode {
    /** one row per session, like FreeRADIUS {@code radacct} (default) */
    SESSIONS,
    /** sessions plus an immutable history of applied events */
    SESSIONS_AND_EVENTS;

    public static StorageMode parse(String value) {
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "sessions" -> SESSIONS;
            case "sessions+events", "sessions_and_events" -> SESSIONS_AND_EVENTS;
            default -> throw new IllegalArgumentException("mode: expected sessions or sessions+events, got " + value);
        };
    }
}
