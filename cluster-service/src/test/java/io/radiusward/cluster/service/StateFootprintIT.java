/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.management.BufferPoolMXBean;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/**
 * The state of a small member at its 2M-session maximum (ADR 0004, 0036), measured in this JVM: the member's state
 * machine and the exporter's replica (no member-only state), fed like {@code OverloadIT}'s load generator — a Start
 * and an Interim per session, each with its own User-Name, a NAS-Identifier and the NAS's address. Heap after a full
 * GC and direct memory must stay within what a 1 GiB member leaves for them. In seconds, without containers: the
 * guard that {@code OverloadIT} (linux tests) would otherwise be the first to trip.
 */
class StateFootprintIT {

    static final int SESSIONS = 2_000_000;

    @Test
    void twoMillionSessionsFitASmallMember() {
        long heapBefore = usedHeap();
        long directBefore = direct();
        AccountingStateMachine member = machine();
        AccountingStateMachine replica = machine();
        replica.memberState(false);
        byte[] attributes = new byte[128];
        UnsafeBuffer raw = new UnsafeBuffer(attributes);
        UnsafeBuffer identity = new UnsafeBuffer(new byte[SessionStore.IDENTITY_SIZE]);
        for (int status : new int[] {AccountingStateMachine.STATUS_START, AccountingStateMachine.STATUS_INTERIM}) {
            long now = status == AccountingStateMachine.STATUS_START ? 1_000_000 : 61_000_000;
            for (int s = 0; s < SESSIONS; s++) {
                String id = String.format("%016x", s);
                int length = attributes(attributes, id);
                int n = SessionIdentity.extract(raw, 0, length, identity, 0);
                long user = 0x9E37_79B9_7F4A_7C15L * (s + 1);
                for (AccountingStateMachine sm : new AccountingStateMachine[] {member, replica}) {
                    sm.apply(
                            s * 0x9E37_79B9_7F4A_7C15L + 1,
                            s,
                            s * 31L + status,
                            now + s,
                            7,
                            status,
                            AccountingStateMachine.FLAG_SESSION_TIME,
                            status == AccountingStateMachine.STATUS_START ? 0 : 60,
                            1_780_000_000L,
                            0,
                            0,
                            0,
                            user,
                            0,
                            identity,
                            0,
                            n,
                            now + s / 1000);
                }
            }
        }
        assertThat(member.store().activeCount()).isEqualTo(SESSIONS);
        assertThat(replica.store().activeCount()).isEqualTo(SESSIONS);
        long heap = usedHeap() - heapBefore;
        long offHeap = direct() - directBefore;
        System.out.printf(
                "state footprint at %,d sessions: heap %d MiB, direct %d MiB (member store %d MiB, replica store %d"
                        + " MiB)%n",
                SESSIONS,
                heap >> 20,
                offHeap >> 20,
                member.store().footprintBytes() >> 20,
                replica.store().footprintBytes() >> 20);
        // a 1 GiB member: heap 256 MB (the rest of the service needs most of it), direct memory 576 MB (ADR 0004)
        assertThat(heap).as("state on the heap: indexes only").isLessThan(128L << 20);
        assertThat(offHeap).as("records off-heap, member and replica").isLessThan(512L << 20);
        assertThat(member.digest()).isNotZero(); // keep both alive until measured
        assertThat(replica.digest()).isNotZero();
    }

    private static AccountingStateMachine machine() {
        AccountingStateMachine sm = new AccountingStateMachine(
                new AccountingStateMachine.Settings(SESSIONS, 3_600_000, 7_200_000, 900_000, 7, 100_000));
        for (int m = 0; m < 3; m++) {
            sm.reportMemberVersion(m, 7, 3, false);
        }
        return sm;
    }

    /** Acct-Session-Id, User-Name, NAS-Identifier, NAS-IP-Address, as the load generator sends them. */
    private static int attributes(byte[] out, String sessionId) {
        int at = 0;
        at = put(out, at, 44, sessionId.getBytes(StandardCharsets.US_ASCII));
        at = put(out, at, 1, (sessionId + "@load.example").getBytes(StandardCharsets.US_ASCII));
        at = put(out, at, 32, "ap-0042".getBytes(StandardCharsets.US_ASCII));
        return put(out, at, 4, new byte[] {127, 0, 0, 1});
    }

    private static int put(byte[] out, int at, int type, byte[] value) {
        out[at] = (byte) type;
        out[at + 1] = (byte) (2 + value.length);
        System.arraycopy(value, 0, out, at + 2, value.length);
        return at + 2 + value.length;
    }

    private static long usedHeap() {
        for (int i = 0; i < 3; i++) {
            System.gc();
        }
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
    }

    private static long direct() {
        return ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class).stream()
                .filter(b -> b.getName().equals("direct"))
                .mapToLong(BufferPoolMXBean::getMemoryUsed)
                .sum();
    }
}
