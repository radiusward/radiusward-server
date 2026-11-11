/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import java.lang.management.ManagementFactory;
import org.junit.jupiter.api.Test;

/** Steady state (interims and duplicates on existing sessions) must not allocate. */
@Epic("Cluster")
@Feature("No allocation in the state machine")
class StateMachineAllocationIT {

    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    @Test
    void interimsDoNotAllocate() {
        int sessions = 100_000;
        AccountingStateMachine sm = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(1_000_000));
        for (int s = 0; s < sessions; s++) {
            sm.apply(s, s, s, 1, s % 100, AccountingStateMachine.STATUS_START, 1, 0, 0, 0, 0, 1000);
        }
        long time = 0;
        for (int round = 0; round < 5; round++) { // warm-up
            time = drive(sm, sessions, time);
        }
        long before = THREADS.getCurrentThreadAllocatedBytes();
        for (int round = 0; round < 10; round++) { // 1M interims + 1M duplicates
            time = drive(sm, sessions, time);
        }
        long allocated = THREADS.getCurrentThreadAllocatedBytes() - before;
        assertThat(sm.applied()).isEqualTo(sessions + 15L * sessions);
        assertThat(allocated).as("bytes allocated by 2M commands").isLessThan(4096);
    }

    private static long drive(AccountingStateMachine sm, int sessions, long time) {
        time += 60;
        for (int s = 0; s < sessions; s++) {
            sm.apply(
                    s,
                    s,
                    s,
                    time,
                    s % 100,
                    AccountingStateMachine.STATUS_INTERIM,
                    1,
                    time,
                    0,
                    time * 10,
                    0,
                    time * 1000);
            sm.apply(
                    s,
                    s,
                    s,
                    time,
                    s % 100,
                    AccountingStateMachine.STATUS_INTERIM,
                    1,
                    time,
                    0,
                    time * 10,
                    0,
                    time * 1000);
        }
        return time;
    }
}
