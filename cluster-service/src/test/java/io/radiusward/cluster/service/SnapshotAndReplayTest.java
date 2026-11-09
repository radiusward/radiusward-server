/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class SnapshotAndReplayTest {

    private static List<byte[]> snapshot(AccountingStateMachine sm) {
        List<byte[]> messages = new ArrayList<>();
        new SnapshotCodec().write(sm, (buffer, offset, length) -> {
            byte[] copy = new byte[length];
            buffer.getBytes(offset, copy);
            messages.add(copy);
        });
        return messages;
    }

    private static AccountingStateMachine restore(List<byte[]> messages) {
        AccountingStateMachine sm = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(1_000_000));
        SnapshotCodec codec = new SnapshotCodec();
        for (byte[] m : messages) {
            codec.onMessage(sm, new UnsafeBuffer(m), 0, m.length);
        }
        assertThat(codec.complete()).isTrue();
        return sm;
    }

    @Test
    void roundTripPreservesStateAndBehaviour() {
        Random random = new Random(7);
        List<DuplicatesPropertyTest.Event> events = DuplicatesPropertyTest.cleanStream(random, 2_000);
        AccountingStateMachine original = DuplicatesPropertyTest.run(events);
        original.apply(0, 0, 11, 12, 1, AccountingStateMachine.STATUS_ACCOUNTING_ON, 0, 0, 0, 0, 0, 5_000_000);
        original.timerScheduled(true);

        List<byte[]> messages = snapshot(original);
        assertThat(messages.size()).as("chunked").isGreaterThan(3);
        AccountingStateMachine restored = restore(messages);

        assertThat(restored.digest()).isEqualTo(original.digest());
        assertThat(restored.applied()).isEqualTo(original.applied());
        assertThat(restored.duplicates()).isEqualTo(original.duplicates());
        assertThat(restored.store().size()).isEqualTo(original.store().size());
        assertThat(restored.store().activeCount()).isEqualTo(original.store().activeCount());
        assertThat(restored.window().size()).isEqualTo(original.window().size());
        assertThat(restored.timerScheduled()).isTrue();

        // every event replayed after restore is a duplicate or stale on both
        for (DuplicatesPropertyTest.Event e : events.subList(events.size() - 200, events.size())) {
            int a = original.apply(
                    e.session(),
                    e.session() * 7,
                    e.session() * 31 + e.status(),
                    e.sessionTime(),
                    e.nas(),
                    e.status(),
                    AccountingStateMachine.FLAG_SESSION_TIME,
                    e.sessionTime(),
                    0,
                    e.octets(),
                    0,
                    6_000_000);
            int b = restored.apply(
                    e.session(),
                    e.session() * 7,
                    e.session() * 31 + e.status(),
                    e.sessionTime(),
                    e.nas(),
                    e.status(),
                    AccountingStateMachine.FLAG_SESSION_TIME,
                    e.sessionTime(),
                    0,
                    e.octets(),
                    0,
                    6_000_000);
            assertThat(b).isEqualTo(a).isNotEqualTo(Outcomes.APPLIED);
        }
        assertThat(restored.applied()).isEqualTo(original.applied());
        assertThat(original.apply(
                        0, 0, 11, 12, 1, AccountingStateMachine.STATUS_ACCOUNTING_ON, 0, 0, 0, 0, 0, 5_100_000))
                .isEqualTo(Outcomes.DUPLICATE);
        assertThat(restored.apply(
                        0, 0, 11, 12, 1, AccountingStateMachine.STATUS_ACCOUNTING_ON, 0, 0, 0, 0, 0, 5_100_000))
                .isEqualTo(Outcomes.DUPLICATE);
    }

    @Test
    void snapshotMidStreamThenReplayEqualsContinuousRun() {
        List<DuplicatesPropertyTest.Event> events = DuplicatesPropertyTest.cleanStream(new Random(3), 1_000);
        int half = events.size() / 2;
        AccountingStateMachine continuous = DuplicatesPropertyTest.run(events);

        AccountingStateMachine first = DuplicatesPropertyTest.run(events.subList(0, half));
        AccountingStateMachine resumed = restore(snapshot(first));
        long now = 1_000 + half * 10L;
        for (DuplicatesPropertyTest.Event e : events.subList(half, events.size())) {
            now += 10;
            resumed.apply(
                    e.session(),
                    e.session() * 7,
                    e.session() * 31 + e.status(),
                    e.sessionTime(),
                    e.nas(),
                    e.status(),
                    AccountingStateMachine.FLAG_SESSION_TIME,
                    e.sessionTime(),
                    0,
                    e.octets(),
                    0,
                    now);
        }
        assertThat(resumed.digest()).isEqualTo(continuous.digest());
        assertThat(resumed.store().size()).isEqualTo(continuous.store().size());
        assertThat(resumed.sweep(100_000_000)).isEqualTo(continuous.sweep(100_000_000));
        assertThat(resumed.digest()).isEqualTo(continuous.digest());
    }

    @Test
    void idleTimeoutPerNasEntrySurvivesASnapshot() {
        AccountingStateMachine sm = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(1_000));
        sm.apply(1, 1, 11, 0, 5, AccountingStateMachine.STATUS_START, 0, 0, 0, 0, 0, 15, 1_000);
        sm.apply(2, 2, 21, 0, 5, AccountingStateMachine.STATUS_START, 0, 0, 0, 0, 0, 0, 1_000);
        AccountingStateMachine restored = restore(snapshot(sm));
        assertThat(restored.store().idleMinutes(restored.store().find(1, 1))).isEqualTo(15);
        assertThat(restored.store().idleMinutes(restored.store().find(2, 2))).isZero();
        assertThat(restored.sweep(1_000 + 15 * 60_000))
                .as("only the 15-minute session")
                .isEqualTo(1);
    }

    @Test
    void identicalStreamsGiveIdenticalDigests() {
        List<DuplicatesPropertyTest.Event> events = DuplicatesPropertyTest.cleanStream(new Random(11), 3_000);
        assertThat(DuplicatesPropertyTest.run(events).digest())
                .isEqualTo(DuplicatesPropertyTest.run(new ArrayList<>(events)).digest());
    }

    @Test
    void emptyAndCorruptSnapshots() {
        AccountingStateMachine empty = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(10));
        assertThat(restore(snapshot(empty)).store().size()).isZero();

        List<byte[]> messages =
                snapshot(DuplicatesPropertyTest.run(DuplicatesPropertyTest.cleanStream(new Random(1), 600)));
        messages.remove(1); // lose a session chunk
        assertThatThrownBy(() -> restore(messages)).hasMessageContaining("snapshot incomplete");
    }
}
