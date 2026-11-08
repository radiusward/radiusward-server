/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

/** Results of {@link AccountingStateMachine#apply}; the first three are acknowledged to the NAS. */
public final class Outcomes {

    public static final int APPLIED = 0;
    public static final int DUPLICATE = 1;
    public static final int STALE = 2;
    public static final int REJECTED_CAPACITY = 3;

    private Outcomes() {}

    public static boolean acknowledged(int outcome) {
        return outcome <= STALE;
    }
}
