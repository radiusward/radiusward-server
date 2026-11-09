/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

/** Results of {@link AccountingStateMachine#apply}; the first four are acknowledged to the NAS. */
public final class Outcomes {

    public static final int APPLIED = 0;
    public static final int DUPLICATE = 1;
    public static final int STALE = 2;
    /**
     * A Start that arrived after the session's Interim (or Stop): it only completes the session (start key, start
     * time); the session's progress is kept.
     */
    public static final int MERGED = 3;

    public static final int REJECTED_CAPACITY = 4;
    /** Not applied: a required sink is more than its {@code maxLag} behind (lag policy {@code block}). */
    public static final int REJECTED_EXPORT_LAG = 5;

    private Outcomes() {}

    public static boolean acknowledged(int outcome) {
        return outcome <= MERGED;
    }
}
