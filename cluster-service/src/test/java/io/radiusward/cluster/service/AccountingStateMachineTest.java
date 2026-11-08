/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static io.radiusward.cluster.service.AccountingStateMachine.FLAG_EVENT_TIMESTAMP;
import static io.radiusward.cluster.service.AccountingStateMachine.FLAG_SESSION_TIME;
import static io.radiusward.cluster.service.AccountingStateMachine.STATUS_ACCOUNTING_ON;
import static io.radiusward.cluster.service.AccountingStateMachine.STATUS_INTERIM;
import static io.radiusward.cluster.service.AccountingStateMachine.STATUS_START;
import static io.radiusward.cluster.service.AccountingStateMachine.STATUS_STOP;
import static io.radiusward.cluster.service.Outcomes.APPLIED;
import static io.radiusward.cluster.service.Outcomes.DUPLICATE;
import static io.radiusward.cluster.service.Outcomes.REJECTED_CAPACITY;
import static io.radiusward.cluster.service.Outcomes.STALE;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AccountingStateMachineTest {

    static final int NAS = 5;
    static final int BOTH = FLAG_SESSION_TIME | FLAG_EVENT_TIMESTAMP;

    private final AccountingStateMachine sm =
            new AccountingStateMachine(new AccountingStateMachine.Settings(10, 3_600_000, 7_200_000, 900_000));

    /** A session event; the exact key is derived from session, status and time like the gateway does. */
    int event(long session, int status, long sessionTime, long octets, long now) {
        return sm.apply(
                session,
                ~session,
                session * 31 + status,
                sessionTime,
                NAS,
                status,
                BOTH,
                sessionTime,
                1_780_000_000L + sessionTime,
                octets,
                octets / 2,
                now);
    }

    int session(long session) {
        return sm.store().find(session, ~session);
    }

    @Test
    void startInterimStop() {
        assertThat(event(1, STATUS_START, 0, 0, 1000)).isEqualTo(APPLIED);
        assertThat(event(1, STATUS_INTERIM, 300, 1000, 301_000)).isEqualTo(APPLIED);
        assertThat(event(1, STATUS_STOP, 600, 2000, 601_000)).isEqualTo(APPLIED);
        int slot = session(1);
        assertThat(sm.store().state(slot)).isEqualTo(SessionStore.STOPPED);
        assertThat(sm.store().sessionTime(slot)).isEqualTo(600);
        assertThat(sm.store().inputOctets(slot)).isEqualTo(2000);
        assertThat(sm.store().tombstoneUntil(slot)).isEqualTo((601_000 + 3_600_000) / 1000);
        assertThat(sm.applied()).isEqualTo(3);
    }

    @Test
    void startDuplicates() {
        assertThat(event(1, STATUS_START, 0, 0, 1000)).isEqualTo(APPLIED);
        assertThat(event(1, STATUS_START, 0, 0, 2000)).isEqualTo(DUPLICATE);
        event(1, STATUS_INTERIM, 300, 10, 3000);
        assertThat(event(1, STATUS_START, 0, 0, 4000))
                .as("late retransmit of the start")
                .isEqualTo(DUPLICATE);
        assertThat(sm.duplicates()).isEqualTo(2);
    }

    @Test
    void startWithNewKeyRestartsTheSession() {
        event(1, STATUS_START, 0, 0, 1000);
        event(1, STATUS_STOP, 100, 50, 2000);
        // same session id, different start (event timestamp) → new instance
        assertThat(sm.apply(1, ~1L, 999, 999, NAS, STATUS_START, BOTH, 0, 1_790_000_000L, 0, 0, 3000))
                .isEqualTo(APPLIED);
        assertThat(sm.store().state(session(1))).isEqualTo(SessionStore.ACTIVE);
        assertThat(sm.store().tombstoneUntil(session(1))).isZero();
    }

    @Test
    void interimProgress() {
        event(1, STATUS_START, 0, 0, 1000);
        assertThat(event(1, STATUS_INTERIM, 300, 1000, 2000)).isEqualTo(APPLIED);
        assertThat(event(1, STATUS_INTERIM, 300, 1000, 3000)).isEqualTo(DUPLICATE);
        assertThat(event(1, STATUS_INTERIM, 200, 500, 4000)).isEqualTo(STALE);
        assertThat(event(1, STATUS_INTERIM, 600, 3000, 5000)).isEqualTo(APPLIED);
        assertThat(sm.store().sessionTime(session(1))).isEqualTo(600);
        assertThat(sm.stale()).isEqualTo(1);
    }

    @Test
    void firstInterimAfterStartIsProgressEvenWithSameTimestampAndNoTraffic() {
        // Start: event timestamp only (as most NAS send it); Interim in the same second, 60 s session time
        sm.apply(6, 6, 61, 0, NAS, STATUS_START, FLAG_EVENT_TIMESTAMP, 0, 1_780_000_000L, 0, 0, 1000);
        assertThat(sm.apply(6, 6, 62, 60, NAS, STATUS_INTERIM, BOTH, 60, 1_780_000_000L, 0, 0, 2000))
                .isEqualTo(APPLIED);
        assertThat(sm.apply(6, 6, 62, 60, NAS, STATUS_INTERIM, BOTH, 60, 1_780_000_000L, 0, 0, 3000))
                .isEqualTo(DUPLICATE);
    }

    @Test
    void interimWithoutTimeComparesOctets() {
        sm.apply(2, 2, 2, 2, NAS, STATUS_START, 0, 0, 0, 0, 0, 1000);
        assertThat(sm.apply(2, 2, 3, 3, NAS, STATUS_INTERIM, 0, 0, 0, 100, 0, 2000))
                .isEqualTo(APPLIED);
        assertThat(sm.apply(2, 2, 3, 3, NAS, STATUS_INTERIM, 0, 0, 0, 100, 0, 3000))
                .isEqualTo(DUPLICATE);
        assertThat(sm.apply(2, 2, 4, 4, NAS, STATUS_INTERIM, 0, 0, 0, 50, 0, 4000))
                .isEqualTo(STALE);
        assertThat(sm.apply(2, 2, 5, 5, NAS, STATUS_INTERIM, FLAG_EVENT_TIMESTAMP, 0, 10, 50, 0, 5000))
                .as("stored session has no event timestamp: fall back to octets")
                .isEqualTo(STALE);
        assertThat(sm.apply(2, 2, 6, 6, NAS, STATUS_INTERIM, FLAG_SESSION_TIME, 30, 0, 50, 0, 6000))
                .as("stored session has no session time: it counts as 0")
                .isEqualTo(APPLIED);
    }

    @Test
    void interimForUnknownSessionCreatesItAndAfterStopIsStale() {
        assertThat(event(3, STATUS_INTERIM, 300, 10, 1000)).isEqualTo(APPLIED);
        assertThat(sm.store().state(session(3))).isEqualTo(SessionStore.ACTIVE);
        event(3, STATUS_STOP, 400, 20, 2000);
        assertThat(event(3, STATUS_INTERIM, 500, 30, 3000)).isEqualTo(STALE);
    }

    @Test
    void stopDuplicatesAndStopWithoutStart() {
        assertThat(event(4, STATUS_STOP, 100, 10, 1000)).isEqualTo(APPLIED);
        assertThat(event(4, STATUS_STOP, 100, 10, 2000)).isEqualTo(DUPLICATE);
        assertThat(sm.store().state(session(4))).isEqualTo(SessionStore.STOPPED);
    }

    @Test
    void accountingOnStopsAllSessionsOfTheNasOnce() {
        event(1, STATUS_START, 0, 0, 1000);
        event(2, STATUS_START, 0, 0, 1000);
        sm.apply(9, ~9L, 9, 9, NAS + 1, STATUS_START, BOTH, 0, 1, 0, 0, 1000); // other NAS
        assertThat(sm.apply(0, 0, 77, 1, NAS, STATUS_ACCOUNTING_ON, FLAG_EVENT_TIMESTAMP, 0, 5, 0, 0, 2000))
                .isEqualTo(APPLIED);
        assertThat(sm.store().state(session(1))).isEqualTo(SessionStore.STOPPED);
        assertThat(sm.store().state(session(2))).isEqualTo(SessionStore.STOPPED);
        assertThat(sm.store().state(sm.store().find(9, ~9L))).isEqualTo(SessionStore.ACTIVE);
        assertThat(sm.apply(0, 0, 77, 1, NAS, STATUS_ACCOUNTING_ON, FLAG_EVENT_TIMESTAMP, 0, 5, 0, 0, 3000))
                .isEqualTo(DUPLICATE);
        // after the window the same key is a new event
        assertThat(sm.apply(0, 0, 77, 1, NAS, STATUS_ACCOUNTING_ON, FLAG_EVENT_TIMESTAMP, 0, 5, 0, 0, 2000 + 900_000))
                .isEqualTo(APPLIED);
    }

    @Test
    void otherStatusTypesUseTheExactWindow() {
        assertThat(sm.apply(0, 0, 1, 2, NAS, 15, 0, 0, 0, 0, 0, 1000)).isEqualTo(APPLIED);
        assertThat(sm.apply(0, 0, 1, 2, NAS, 15, 0, 0, 0, 0, 0, 2000)).isEqualTo(DUPLICATE);
    }

    @Test
    void capacity() {
        for (int i = 0; i < 10; i++) {
            assertThat(event(100 + i, STATUS_START, 0, 0, 1000)).isEqualTo(APPLIED);
        }
        assertThat(event(200, STATUS_START, 0, 0, 1000)).isEqualTo(REJECTED_CAPACITY);
        assertThat(event(201, STATUS_INTERIM, 10, 0, 1000)).isEqualTo(REJECTED_CAPACITY);
        assertThat(event(202, STATUS_STOP, 10, 0, 1000))
                .as("a stop is never rejected")
                .isEqualTo(APPLIED);
        assertThat(sm.rejected()).isEqualTo(2);
        assertThat(Outcomes.acknowledged(REJECTED_CAPACITY)).isFalse();
        assertThat(Outcomes.acknowledged(STALE)).isTrue();
    }

    @Test
    void sweepRemovesExpiredTombstonesAndIdleSessions() {
        event(1, STATUS_START, 0, 0, 0);
        event(2, STATUS_START, 0, 0, 0);
        event(2, STATUS_STOP, 10, 0, 10_000);
        sm.apply(0, 0, 5, 5, NAS, 15, 0, 0, 0, 0, 0, 0);
        assertThat(sm.sweep(60_000)).isZero();
        assertThat(sm.sweep(10_000 + 3_600_000))
                .as("tombstone of session 2 expired")
                .isEqualTo(1);
        assertThat(session(2)).isEqualTo(-1);
        assertThat(sm.window().size()).isZero();
        assertThat(sm.sweep(7_200_000)).as("session 1 idle for 2 h").isEqualTo(1);
        assertThat(sm.expired()).isEqualTo(1);
        assertThat(sm.store().size()).isZero();
    }

    @Test
    void digestChangesOnlyWithState() {
        long d0 = sm.digest();
        event(1, STATUS_START, 0, 0, 1000);
        long d1 = sm.digest();
        assertThat(d1).isNotEqualTo(d0);
        event(1, STATUS_START, 0, 0, 2000); // duplicate
        assertThat(sm.digest()).isEqualTo(d1);
    }
}
