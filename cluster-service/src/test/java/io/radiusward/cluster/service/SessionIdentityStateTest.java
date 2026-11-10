/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** Identifying attributes and first event of sessions in the replicated state, from state version 7 (ADR 0036). */
class SessionIdentityStateTest {

    static final int NAS = 3;
    static final long USER = 0x5e55_1d00_0001L;

    static AccountingStateMachine machine(int supported) {
        return new AccountingStateMachine(
                new AccountingStateMachine.Settings(100, 3_600_000, 7_200_000, 900_000, supported, 100));
    }

    static void activate(AccountingStateMachine sm, int version) {
        for (int m = 0; m < 3; m++) {
            sm.reportMemberVersion(m, version, 3, false);
        }
        assertThat(sm.atLeast(version)).isTrue();
    }

    static int event(AccountingStateMachine sm, long session, int status, String sessionId, String user, long now) {
        byte[] identity =
                SessionIdentityTest.attrs(SessionIdentityTest.attr(44, sessionId), SessionIdentityTest.attr(1, user));
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
                USER,
                0,
                new UnsafeBuffer(identity),
                0,
                identity.length,
                now);
    }

    static String user(AccountingStateMachine sm, long session) {
        int slot = sm.store().find(session, ~session);
        UnsafeBuffer out = new UnsafeBuffer(new byte[SessionStore.IDENTITY_SIZE]);
        int n = sm.store().identity(slot, out, 0);
        return SessionIdentity.string(out, 0, n, 1);
    }

    @Test
    void keptFromVersion7OnAndReplacedByEveryEvent() {
        AccountingStateMachine sm = machine(7);
        activate(sm, 6);
        event(sm, 1, AccountingStateMachine.STATUS_START, "s-1", "alice", 1_000);
        assertThat(user(sm, 1))
                .as("version 6 active: not kept, as by older members")
                .isNull();
        assertThat(sm.store().firstSeen(sm.store().find(1, ~1L))).isZero();

        activate(sm, 7);
        event(sm, 1, AccountingStateMachine.STATUS_INTERIM, "s-1", "alice", 61_000);
        assertThat(user(sm, 1)).isEqualTo("alice");
        int slot = sm.store().find(1, ~1L);
        assertThat(sm.store().firstSeen(slot))
                .as("the first event since version 7")
                .isEqualTo(61);

        event(sm, 1, AccountingStateMachine.STATUS_INTERIM, "s-1", "alice@corp", 121_000);
        assertThat(user(sm, 1)).as("the latest event's").isEqualTo("alice@corp");
        assertThat(sm.store().firstSeen(slot)).as("set once").isEqualTo(61);
    }

    @Test
    void aReplicaKeepsNone() {
        AccountingStateMachine replica = machine(7);
        replica.memberState(false);
        activate(replica, 7);
        event(replica, 1, AccountingStateMachine.STATUS_START, "s-1", "alice", 1_000);
        assertThat(user(replica, 1)).isNull();
        assertThat(replica.store().devicesOnline(USER))
                .as("no users either (ADR 0023)")
                .isZero();
        assertThat(replica.store().firstSeen(replica.store().find(1, ~1L)))
                .as("member state only")
                .isZero();
        assertThat(replica.store().footprintBytes())
                .as("no identity chunk allocated")
                .isLessThan(machineWithIdentity().store().footprintBytes());
    }

    private static AccountingStateMachine machineWithIdentity() {
        AccountingStateMachine sm = machine(7);
        activate(sm, 7);
        event(sm, 1, AccountingStateMachine.STATUS_START, "s-1", "alice", 1_000);
        return sm;
    }

    @Test
    void membersAgreeAndSnapshotsKeepThem() {
        AccountingStateMachine a = machine(7);
        AccountingStateMachine b = machine(7);
        for (AccountingStateMachine sm : List.of(a, b)) {
            activate(sm, 7);
            event(sm, 1, AccountingStateMachine.STATUS_START, "s-1", "alice", 1_000);
            event(sm, 2, AccountingStateMachine.STATUS_START, "s-2", "bob", 2_000);
            event(sm, 2, AccountingStateMachine.STATUS_STOP, "s-2", "bob", 3_000);
        }
        assertThat(a.digest()).isEqualTo(b.digest());

        List<byte[]> messages = new ArrayList<>();
        new SnapshotCodec().write(a, (buffer, offset, length) -> {
            byte[] copy = new byte[length];
            buffer.getBytes(offset, copy);
            messages.add(copy);
        });
        AccountingStateMachine restored = machine(7);
        SnapshotCodec codec = new SnapshotCodec();
        for (byte[] m : messages) {
            codec.onMessage(restored, new UnsafeBuffer(m), 0, m.length);
        }
        assertThat(codec.complete()).isTrue();
        assertThat(restored.digest()).isEqualTo(a.digest());
        assertThat(user(restored, 1)).isEqualTo("alice");
        assertThat(restored.store().firstSeen(restored.store().find(1, ~1L))).isEqualTo(1);

        for (AccountingStateMachine sm : List.of(a, restored)) { // both go on alike
            event(sm, 1, AccountingStateMachine.STATUS_INTERIM, "s-1", "alice2", 9_000);
        }
        assertThat(restored.digest()).isEqualTo(a.digest());
    }
}
