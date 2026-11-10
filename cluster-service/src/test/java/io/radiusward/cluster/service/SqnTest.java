/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.SqnNextEncoder;
import java.util.ArrayList;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** SIM sequence numbers in the replicated state (state version 8, ADR 0061). */
class SqnTest {

    static final long SIM_A = 0x2620_1000_0000_0001L;
    static final long SIM_B = 0x2620_1000_0000_0002L;

    static AccountingStateMachine v8(int maxSubscribers) {
        AccountingStateMachine sm = new AccountingStateMachine(
                new AccountingStateMachine.Settings(100, 3_600_000, 7_200_000, 900_000, 8, 100, maxSubscribers));
        for (int m = 0; m < 3; m++) {
            sm.reportMemberVersion(m, 8, 3, false);
        }
        assertThat(sm.atLeast(8)).isTrue();
        return sm;
    }

    @Test
    void numbersGoUpBySeqAndRespectTheFloor() {
        AccountingStateMachine sm = v8(10);
        assertThat(sm.nextSqn(SIM_A, 0)).as("SEQ 1, IND 0").isEqualTo(32);
        assertThat(sm.nextSqn(SIM_A, 0)).isEqualTo(64);
        assertThat(sm.nextSqn(SIM_A, 1000)).as("above the store's SIM-SQN").isEqualTo(1024);
        assertThat(sm.nextSqn(SIM_A, 10)).as("a lower floor does not go back").isEqualTo(1056);
        assertThat(sm.nextSqn(SIM_A, 5000))
                .as("resynchronised to the USIM's SQN")
                .isEqualTo(5024);
        assertThat(sm.nextSqn(SIM_B, 31)).as("subscribers count apart").isEqualTo(32);
        assertThat(sm.sqn(SIM_A)).isEqualTo(5024);
        assertThat(sm.nextSqn(SIM_B, (1L << 48) + 5)).as("never beyond 48 bits").isLessThan(1L << 48);
        assertThat(sm.nextSqn(SIM_A, -7)).as("a negative floor counts as none").isEqualTo(5056);
    }

    @Test
    void capacityAndTheVersionGate() {
        AccountingStateMachine full = v8(1);
        assertThat(full.nextSqn(SIM_A, 0)).isEqualTo(32);
        assertThat(full.nextSqn(SIM_B, 0)).isEqualTo(AccountingStateMachine.SQN_CAPACITY);
        assertThat(full.nextSqn(SIM_A, 0)).as("known subscribers go on").isEqualTo(64);

        AccountingStateMachine old = new AccountingStateMachine(
                new AccountingStateMachine.Settings(100, 3_600_000, 7_200_000, 900_000, 7, 100, 10));
        assertThat(old.nextSqn(SIM_A, 0)).isEqualTo(AccountingStateMachine.SQN_UNSUPPORTED);
        assertThat(old.sqns()).isEmpty();
    }

    @Test
    void appliedFromTheLogAndRestoredFromASnapshot() {
        AccountingStateMachine sm = v8(10);
        LogApplier applier = new LogApplier(sm);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[64]);
        SqnNextEncoder encoder = new SqnNextEncoder()
                .wrapAndApplyHeader(buffer, 0, new MessageHeaderEncoder())
                .correlationId(77)
                .gatewayId(1)
                .subscriberKey(SIM_A)
                .floor(100);
        assertThat(applier.apply(buffer, 0, 1, 1_000)).isEqualTo(LogApplier.SQN_NEXT);
        assertThat(applier.sqnResult()).isEqualTo(128);
        assertThat(applier.sqnRequest().correlationId()).isEqualTo(77);
        assertThat(encoder.encodedLength()).isPositive();
        long before = sm.digest();
        sm.nextSqn(SIM_B, 0);
        assertThat(sm.digest()).as("part of the state digest").isNotEqualTo(before);

        List<byte[]> messages = new ArrayList<>();
        new SnapshotCodec().write(sm, (b, offset, length) -> {
            byte[] copy = new byte[length];
            b.getBytes(offset, copy);
            messages.add(copy);
        });
        AccountingStateMachine restored = v8(10);
        SnapshotCodec codec = new SnapshotCodec();
        for (byte[] m : messages) {
            codec.onMessage(restored, new UnsafeBuffer(m), 0, m.length);
        }
        assertThat(codec.complete()).isTrue();
        assertThat(restored.sqn(SIM_A)).isEqualTo(128);
        assertThat(restored.sqn(SIM_B)).isEqualTo(32);
        assertThat(restored.digest()).isEqualTo(sm.digest());
        assertThat(restored.nextSqn(SIM_A, 0)).isEqualTo(sm.nextSqn(SIM_A, 0));
    }

    @Test
    void manySubscribersSpanSeveralSnapshotChunks() {
        AccountingStateMachine sm = v8(5_000);
        for (long k = 1; k <= 2_500; k++) {
            sm.nextSqn(k, k);
        }
        List<byte[]> messages = new ArrayList<>();
        new SnapshotCodec().write(sm, (b, offset, length) -> {
            byte[] copy = new byte[length];
            b.getBytes(offset, copy);
            messages.add(copy);
        });
        AccountingStateMachine restored = v8(5_000);
        SnapshotCodec codec = new SnapshotCodec();
        for (byte[] m : messages) {
            codec.onMessage(restored, new UnsafeBuffer(m), 0, m.length);
        }
        assertThat(codec.complete()).isTrue();
        assertThat(restored.sqns().size()).isEqualTo(2_500);
        assertThat(restored.sqn(2_500)).isEqualTo(sm.sqn(2_500));
    }
}
