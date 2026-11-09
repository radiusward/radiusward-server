/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static io.radiusward.cluster.service.AccountingStateMachine.RESERVATION_CAPACITY;
import static io.radiusward.cluster.service.AccountingStateMachine.RESERVATION_DENIED;
import static io.radiusward.cluster.service.AccountingStateMachine.RESERVATION_GRANTED;
import static io.radiusward.cluster.service.AccountingStateMachine.RESERVATION_UNSUPPORTED;
import static io.radiusward.cluster.service.AccountingStateMachine.STATUS_ACCOUNTING_ON;
import static io.radiusward.cluster.service.AccountingStateMachine.STATUS_INTERIM;
import static io.radiusward.cluster.service.AccountingStateMachine.STATUS_START;
import static io.radiusward.cluster.service.AccountingStateMachine.STATUS_STOP;
import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.protocol.AccountingCommandEncoder;
import io.radiusward.protocol.AuthReservationEncoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import java.util.ArrayList;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** Simultaneous use (state version 6, ADR 0023): users and devices of sessions, reservations. */
class SimultaneousUseTest {

    static final int NAS = 5;
    static final long USER = 0x1234_5678_9abcL;
    static final long OTHER = 0x0fed_cba9_8765L;
    static final long A = 0xaabb_cc00_0001L;
    static final long B = 0xaabb_cc00_0002L;
    static final long C = 0xaabb_cc00_0003L;
    static final long TTL = 60_000;

    static AccountingStateMachine v6(int maxReservations) {
        AccountingStateMachine sm = new AccountingStateMachine(
                new AccountingStateMachine.Settings(100, 3_600_000, 7_200_000, 900_000, 6, maxReservations));
        for (int m = 0; m < 3; m++) {
            sm.reportMemberVersion(m, 6, 3, false); // every member runs it: activated automatically
        }
        assertThat(sm.atLeast(6)).isTrue();
        return sm;
    }

    static int event(AccountingStateMachine sm, long session, int status, long user, long device, long now) {
        return sm.apply(
                session,
                ~session,
                session * 31 + status + now,
                now,
                NAS,
                status,
                AccountingStateMachine.FLAG_SESSION_TIME,
                now / 1000,
                0,
                now,
                0,
                0,
                user,
                device,
                now);
    }

    @Test
    void beforeVersionSixUsersAreIgnoredLikeOlderCodeDoes() {
        AccountingStateMachine newer = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(100), 6);
        AccountingStateMachine older = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(100), 5);
        for (AccountingStateMachine sm : List.of(newer, older)) {
            event(sm, 1, STATUS_START, USER, A, 1_000);
            event(sm, 2, STATUS_START, USER, B, 2_000);
        }
        assertThat(newer.atLeast(6)).isFalse();
        assertThat(newer.reserve(USER, C, 1, TTL, 3_000)).isEqualTo(RESERVATION_UNSUPPORTED);
        assertThat(newer.store().userKey(newer.store().find(1, ~1))).isZero();
        assertThat(newer.store().devicesOnline(USER)).isZero();
        assertThat(newer.digest()).as("same state as code without version 6").isEqualTo(older.digest());
    }

    @Test
    void theLimitCountsDistinctDevicesOnlineAndReserved() {
        AccountingStateMachine sm = v6(100);
        event(sm, 1, STATUS_START, USER, A, 1_000);
        event(sm, 2, STATUS_START, USER, A, 2_000); // a second session of the same device
        event(sm, 3, STATUS_START, OTHER, B, 2_500); // another user's device
        assertThat(sm.store().devicesOnline(USER)).isEqualTo(1);

        assertThat(sm.reserve(USER, B, 2, TTL, 3_000)).isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reserve(USER, C, 2, TTL, 3_100))
                .as("A online + B reserved")
                .isEqualTo(RESERVATION_DENIED);

        event(sm, 4, STATUS_START, USER, B, 4_000); // B starts: its reservation becomes a session
        assertThat(sm.reservations().size()).isZero();
        assertThat(sm.store().devicesOnline(USER)).isEqualTo(2);
        assertThat(sm.reserve(USER, C, 2, TTL, 5_000)).isEqualTo(RESERVATION_DENIED);

        event(sm, 1, STATUS_STOP, USER, A, 6_000);
        assertThat(sm.store().devicesOnline(USER)).as("A still has session 2").isEqualTo(2);
        event(sm, 2, STATUS_STOP, USER, A, 7_000);
        assertThat(sm.store().devicesOnline(USER)).isEqualTo(1);
        assertThat(sm.reserve(USER, C, 2, TTL, 8_000)).isEqualTo(RESERVATION_GRANTED);
    }

    @Test
    void theSameDeviceIsAlwaysLetInAndHoldsOnePlace() {
        AccountingStateMachine sm = v6(100);
        event(sm, 1, STATUS_START, USER, A, 1_000);
        assertThat(sm.reserve(USER, A, 1, TTL, 2_000))
                .as("reconnect of the online device")
                .isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reservations().size()).isZero();

        assertThat(sm.reserve(USER, B, 2, TTL, 3_000)).isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reserve(USER, B, 2, TTL, 4_000)).as("retransmission").isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reservations().size()).isEqualTo(1);
        assertThat(sm.reserve(USER, C, 2, TTL, 5_000)).isEqualTo(RESERVATION_DENIED);
        assertThat(sm.reserve(USER, C, 0, TTL, 5_000)).as("Simultaneous-Use 0").isEqualTo(RESERVATION_DENIED);
    }

    @Test
    void reservationsExpireAndAreSweptAway() {
        AccountingStateMachine sm = v6(100);
        assertThat(sm.reserve(USER, A, 1, TTL, 1_000)).isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reserve(USER, B, 1, TTL, 1_000 + TTL - 1)).isEqualTo(RESERVATION_DENIED);
        assertThat(sm.reserve(USER, B, 1, TTL, 1_000 + TTL))
                .as("A's place expired")
                .isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reservations().size()).isEqualTo(2);
        sm.sweep(1_000 + TTL);
        assertThat(sm.reservations().size()).isEqualTo(1);
        sm.sweep(1_000 + 2 * TTL);
        assertThat(sm.reservations().size()).isZero();
        event(sm, 1, STATUS_START, USER, B, 1_000 + 3 * TTL); // late Start: no reservation to end
        assertThat(sm.store().devicesOnline(USER)).isEqualTo(1);
    }

    @Test
    void unknownDevicesEachCountAndUseUpReservationsByExpiry() {
        AccountingStateMachine sm = v6(100);
        event(sm, 1, STATUS_START, USER, 0, 1_000);
        event(sm, 2, STATUS_START, USER, 0, 1_500);
        assertThat(sm.store().devicesOnline(USER))
                .as("sessions without device count on their own")
                .isEqualTo(2);
        assertThat(sm.reserve(USER, 0, 3, TTL, 2_000)).isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reserve(USER, 0, 3, TTL, 2_100))
                .as("no device to recognise")
                .isEqualTo(RESERVATION_DENIED);
        event(sm, 3, STATUS_START, USER, C, 3_000); // the device was unknown at authentication
        assertThat(sm.reservations().size())
                .as("a Start with a device takes a reservation without one")
                .isZero();

        assertThat(sm.reserve(OTHER, A, 5, TTL, 4_000)).isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reserve(OTHER, B, 5, TTL, 3_000 + TTL)).isEqualTo(RESERVATION_GRANTED);
        event(sm, 4, STATUS_START, OTHER, 0, 5_000);
        assertThat(sm.reservations().size()).isEqualTo(1);
        assertThat(sm.reserve(OTHER, B, 2, TTL, 5_100))
                .as("the reservation expiring first (A) was used; B still holds its own")
                .isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reservations().size()).isEqualTo(1);
    }

    @Test
    void fullReservationTableAnswersCapacity() {
        AccountingStateMachine sm = v6(2);
        assertThat(sm.reserve(USER, A, 5, TTL, 1_000)).isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reserve(OTHER, A, 5, TTL, 1_000)).isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reserve(USER, B, 5, TTL, 1_000)).isEqualTo(RESERVATION_CAPACITY);
    }

    @Test
    void sessionsEndedByTheNasOrTheIdleTimeoutNoLongerCount() {
        AccountingStateMachine sm = v6(100);
        event(sm, 1, STATUS_START, USER, A, 1_000);
        event(sm, 2, STATUS_START, USER, B, 1_000);
        assertThat(sm.store().devicesOnline(USER)).isEqualTo(2);
        sm.apply(0, 0, 77, 78, NAS, STATUS_ACCOUNTING_ON, 0, 0, 0, 0, 0, 0, 0, 0, 2_000);
        assertThat(sm.store().devicesOnline(USER)).isZero();

        event(sm, 3, STATUS_INTERIM, USER, C, 3_000); // created by an Interim
        assertThat(sm.store().devicesOnline(USER)).isEqualTo(1);
        sm.sweep(3_000 + 7_200_000);
        assertThat(sm.store().devicesOnline(USER)).isZero();
    }

    @Test
    void anOlderSessionGetsItsUserWithItsNextEvent() {
        AccountingStateMachine sm = new AccountingStateMachine(
                new AccountingStateMachine.Settings(100, 3_600_000, 7_200_000, 900_000, 6, 100));
        event(sm, 1, STATUS_START, USER, A, 1_000); // before activation
        for (int m = 0; m < 3; m++) {
            sm.reportMemberVersion(m, 6, 3, false);
        }
        assertThat(sm.store().devicesOnline(USER)).isZero();
        event(sm, 1, STATUS_INTERIM, USER, A, 2_000);
        assertThat(sm.store().devicesOnline(USER)).isEqualTo(1);
    }

    @Test
    void usersAndReservationsSurviveASnapshot() {
        AccountingStateMachine sm = v6(100);
        event(sm, 1, STATUS_START, USER, A, 1_000);
        event(sm, 2, STATUS_START, USER, 0, 1_000);
        event(sm, 3, STATUS_START, OTHER, B, 1_000);
        event(sm, 3, STATUS_STOP, OTHER, B, 1_500);
        sm.reserve(USER, B, 5, TTL, 2_000);
        sm.reserve(OTHER, C, 5, TTL, 2_000);

        List<byte[]> messages = new ArrayList<>();
        new SnapshotCodec().write(sm, (buffer, offset, length) -> {
            byte[] copy = new byte[length];
            buffer.getBytes(offset, copy);
            messages.add(copy);
        });
        AccountingStateMachine restored = new AccountingStateMachine(
                new AccountingStateMachine.Settings(100, 3_600_000, 7_200_000, 900_000, 6, 100));
        SnapshotCodec codec = new SnapshotCodec();
        for (byte[] m : messages) {
            codec.onMessage(restored, new UnsafeBuffer(m), 0, m.length);
        }
        assertThat(codec.complete()).isTrue();
        assertThat(restored.digest()).isEqualTo(sm.digest());
        assertThat(restored.store().devicesOnline(USER)).isEqualTo(2);
        assertThat(restored.store().devicesOnline(OTHER)).isZero();
        assertThat(restored.reservations().size()).isEqualTo(2);

        for (AccountingStateMachine m : List.of(sm, restored)) { // both decide alike from here
            assertThat(m.reserve(USER, C, 3, TTL, 3_000)).isEqualTo(RESERVATION_DENIED);
            event(m, 4, STATUS_START, USER, B, 4_000);
            assertThat(m.reserve(USER, B, 3, TTL, 5_000)).isEqualTo(RESERVATION_GRANTED);
            m.sweep(2_000 + TTL);
        }
        assertThat(restored.digest()).isEqualTo(sm.digest());
        assertThat(restored.reservations().size())
                .isEqualTo(sm.reservations().size())
                .isZero();
    }

    @Test
    void theLogCarriesUsersAndReservations() {
        AccountingStateMachine sm = v6(100);
        LogApplier applier = new LogApplier(sm);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        MessageHeaderEncoder header = new MessageHeaderEncoder();
        AccountingCommandEncoder command = new AccountingCommandEncoder();
        command.wrapAndApplyHeader(buffer, 0, header)
                .correlationId(1)
                .nasId(NAS)
                .sessionKeyHi(9)
                .sessionKeyLo(10)
                .exactKeyHi(11)
                .exactKeyLo(12)
                .statusType(STATUS_START)
                .userKey(USER)
                .deviceKey(A);
        command.sessionId("s");
        command.putRawAttributes(new byte[0], 0, 0);
        command.nasDevice("");
        assertThat(applier.apply(buffer, 0, 100, 1_000)).isEqualTo(Outcomes.APPLIED);
        assertThat(sm.store().devicesOnline(USER)).isEqualTo(1);

        AuthReservationEncoder reservation = new AuthReservationEncoder();
        reservation
                .wrapAndApplyHeader(buffer, 0, header)
                .correlationId(77)
                .gatewayId(1)
                .userKey(USER)
                .deviceKey(B)
                .maxDevices(1)
                .ttlSeconds(60);
        assertThat(applier.apply(buffer, 0, 200, 2_000)).isEqualTo(LogApplier.AUTH_RESERVATION);
        assertThat(applier.reservationResult()).isEqualTo(RESERVATION_DENIED);
        assertThat(applier.reservation().correlationId()).isEqualTo(77);
        reservation.maxDevices(2);
        assertThat(applier.apply(buffer, 0, 300, 3_000)).isEqualTo(LogApplier.AUTH_RESERVATION);
        assertThat(applier.reservationResult()).isEqualTo(RESERVATION_GRANTED);
        assertThat(sm.reservations().expiry(0)).isEqualTo(3_000 + 60_000);
    }
}
