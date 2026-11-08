/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static io.radiusward.cluster.service.ExportState.FULL;
import static io.radiusward.cluster.service.ExportState.GRANTED;
import static io.radiusward.cluster.service.ExportState.NOT_OWNER;
import static io.radiusward.cluster.service.ExportState.ON_MAX_LAG_BLOCK;
import static io.radiusward.cluster.service.ExportState.ON_MAX_LAG_DETACH;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class ExportStateTest {

    private static final long LEASE = 10_000;
    private static final long HOUR = 3_600_000;

    private final ExportState state = new ExportState();

    private int checkpoint(String sink, int member, long epoch, long position, long now) {
        return state.checkpoint(sink, member, epoch, position, now, LEASE, true, 0, 4 * HOUR, ON_MAX_LAG_BLOCK, now);
    }

    @Test
    void leaseIsClaimedRenewedAndTakenOverWithANewEpoch() {
        assertThat(checkpoint("pg", 0, 0, 0, 1_000)).isEqualTo(GRANTED);
        int slot = state.find("pg");
        assertThat(state.owner(slot)).isZero();
        assertThat(state.epoch(slot)).isEqualTo(1);

        assertThat(checkpoint("pg", 0, 1, 100, 5_000)).as("renewal").isEqualTo(GRANTED);
        assertThat(state.epoch(slot)).isEqualTo(1);
        assertThat(checkpoint("pg", 1, 0, 0, 6_000)).as("lease still valid").isEqualTo(NOT_OWNER);

        assertThat(checkpoint("pg", 1, 0, 50, 15_001)).as("expired: takeover").isEqualTo(GRANTED);
        assertThat(state.owner(slot)).isEqualTo(1);
        assertThat(state.epoch(slot)).isEqualTo(2);
        assertThat(state.checkpoint(slot)).as("checkpoints never move back").isEqualTo(100);

        assertThat(checkpoint("pg", 0, 1, 200, 16_000))
                .as("old owner is fenced")
                .isEqualTo(NOT_OWNER);
        assertThat(checkpoint("pg", 1, 0, 200, 16_000))
                .as("owner's restarted exporter")
                .isEqualTo(GRANTED);
        assertThat(state.epoch(slot)).isEqualTo(3);
    }

    @Test
    void requiredSinkOverItsByteLimitBlocks() {
        state.checkpoint("pg", 0, 0, 1_000, 0, LEASE, true, 10_000, 0, ON_MAX_LAG_BLOCK, 0);
        assertThat(state.blocks(5_000, 1)).isFalse();
        state.commandProcessed(5_000);
        assertThat(state.blocks(11_001, 2)).isTrue();
        state.checkpoint("pg", 0, 1, 11_000, 2, LEASE, true, 10_000, 0, ON_MAX_LAG_BLOCK, 3);
        assertThat(state.blocks(11_200, 4)).as("caught up again").isFalse();
    }

    @Test
    void idleTimeIsNotLag() {
        checkpoint("pg", 0, 0, 0, 0);
        state.blocks(100, 10);
        state.commandProcessed(100);
        checkpoint("pg", 0, 1, 100, 20); // fully caught up
        // a quiet night, then traffic again: the sink is behind only since the first new entry
        assertThat(state.blocks(200, 8 * HOUR)).isFalse();
        state.commandProcessed(200);
        assertThat(state.blocks(300, 8 * HOUR + 3 * HOUR)).isFalse();
        assertThat(state.blocks(400, 8 * HOUR + 4 * HOUR + 1))
                .as("4 h behind since the first new entry")
                .isTrue();
    }

    @Test
    void optionalSinkDetachesAndReattaches() {
        state.checkpoint("search", 0, 0, 0, 0, LEASE, false, 1_000, 0, ON_MAX_LAG_DETACH, 0);
        state.checkpoint("pg", 1, 0, 0, 0, LEASE, true, 0, 0, ON_MAX_LAG_BLOCK, 0);
        assertThat(state.blocks(2_000, 1)).as("detach never blocks").isFalse();
        state.commandProcessed(2_000);
        assertThat(state.detached(state.find("search"))).isTrue();
        state.checkpoint("pg", 1, 1, 2_000, 1, LEASE, true, 0, 0, ON_MAX_LAG_BLOCK, 2);
        assertThat(state.slowestRequiredCheckpoint())
                .as("detached sink no longer holds the log")
                .isEqualTo(2_000);

        state.checkpoint("search", 0, 1, 1_500, 1, LEASE, false, 1_000, 0, ON_MAX_LAG_DETACH, 3);
        assertThat(state.detached(state.find("search"))).isFalse();
        assertThat(state.slowestRequiredCheckpoint()).isEqualTo(1_500);
    }

    @Test
    void memberFloorWaitsForEveryMemberAndOnlyMovesForward() {
        assertThat(state.memberFloor(3)).as("nobody reported").isZero();
        state.memberPosition(0, 1_000);
        state.memberPosition(1, 2_000);
        assertThat(state.memberFloor(3))
                .as("member 2 never reported: hold everything")
                .isZero();
        state.memberPosition(2, 1_500);
        assertThat(state.memberFloor(3)).isEqualTo(1_000);
        state.memberPosition(0, 500); // a late, older report
        assertThat(state.memberFloor(3)).isEqualTo(1_000);
        state.memberPosition(99, 1); // ignored
        assertThat(state.memberFloor(3)).isEqualTo(1_000);
    }

    @Test
    void resyncMovesTheCheckpointBackAndFencesTheExporter() {
        assertThat(checkpoint("pg", 0, 0, 5_000, 1_000)).isEqualTo(GRANTED);
        int slot = state.find("pg");
        assertThat(state.resync("pg", 1_000)).isTrue();
        assertThat(state.resync("nope", 0)).isFalse();
        assertThat(state.checkpoint(slot)).isEqualTo(1_000);
        assertThat(state.epoch(slot)).as("old exporter fenced").isEqualTo(2);
        assertThat(state.resyncFrom(slot)).isEqualTo(1_000);

        // the old exporter renews with its old epoch and position: granted a new epoch, but its position is ignored
        assertThat(checkpoint("pg", 0, 1, 6_000, 2_000)).isEqualTo(GRANTED);
        assertThat(state.epoch(slot)).isEqualTo(3);
        assertThat(state.checkpoint(slot)).isEqualTo(1_000);
        assertThat(state.resyncFrom(slot))
                .as("still pending: start from the checkpoint")
                .isEqualTo(1_000);

        // the restarted exporter writes past the resync point with the current epoch: done
        assertThat(checkpoint("pg", 0, 3, 1_500, 3_000)).isEqualTo(GRANTED);
        assertThat(state.checkpoint(slot)).isEqualTo(1_500);
        assertThat(state.resyncFrom(slot)).isEqualTo(-1);
    }

    @Test
    void sinkTableIsBounded() {
        for (int i = 0; i < ExportState.MAX_SINKS; i++) {
            assertThat(checkpoint("s" + i, 0, 0, 0, 0)).isEqualTo(GRANTED);
        }
        assertThat(checkpoint("one-too-many", 0, 0, 0, 0)).isEqualTo(FULL);
    }

    @Test
    void sinksSurviveASnapshot() {
        AccountingStateMachine original = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(100));
        ExportState export = original.export();
        export.checkpoint("pg", 2, 0, 4_096, 77, LEASE, true, 0, 4 * HOUR, ON_MAX_LAG_BLOCK, 1_000);
        export.checkpoint("search", 1, 0, 1_024, 55, LEASE, false, 1_000, 0, ON_MAX_LAG_DETACH, 1_000);
        export.blocks(9_000, 2_000);
        export.commandProcessed(9_000);
        export.memberPosition(0, 7_000);
        export.memberPosition(2, 8_000);

        List<byte[]> messages = new ArrayList<>();
        new SnapshotCodec().write(original, (buffer, offset, length) -> {
            byte[] copy = new byte[length];
            buffer.getBytes(offset, copy);
            messages.add(copy);
        });
        AccountingStateMachine restored = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(100));
        SnapshotCodec codec = new SnapshotCodec();
        messages.forEach(m -> codec.onMessage(restored, new UnsafeBuffer(m), 0, m.length));
        assertThat(codec.complete()).isTrue();

        ExportState r = restored.export();
        assertThat(r.count()).isEqualTo(2);
        assertThat(r.memberReported(1)).isFalse();
        assertThat(r.memberPosition(0)).isEqualTo(7_000);
        assertThat(r.memberPosition(2)).isEqualTo(8_000);
        assertThat(r.lastCommandPosition()).isEqualTo(9_000);
        for (int i = 0; i < 2; i++) {
            assertThat(r.name(i)).isEqualTo(export.name(i));
            assertThat(r.checkpoint(i)).isEqualTo(export.checkpoint(i));
            assertThat(r.owner(i)).isEqualTo(export.owner(i));
            assertThat(r.epoch(i)).isEqualTo(export.epoch(i));
            assertThat(r.leaseExpiry(i)).isEqualTo(export.leaseExpiry(i));
            assertThat(r.lastEventTime(i)).isEqualTo(export.lastEventTime(i));
            assertThat(r.behindSince(i)).isEqualTo(export.behindSince(i));
            assertThat(r.required(i)).isEqualTo(export.required(i));
            assertThat(r.maxLagBytes(i)).isEqualTo(export.maxLagBytes(i));
            assertThat(r.maxLagMs(i)).isEqualTo(export.maxLagMs(i));
            assertThat(r.onMaxLag(i)).isEqualTo(export.onMaxLag(i));
            assertThat(r.detached(i)).isEqualTo(export.detached(i));
            assertThat(r.resyncFrom(i)).isEqualTo(export.resyncFrom(i));
        }
    }

    @Test
    void version1SnapshotWithoutSinksStillLoads() {
        AccountingStateMachine original = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(100));
        original.apply(1, 2, 3, 4, 1, AccountingStateMachine.STATUS_START, 0, 0, 0, 0, 0, 1_000);
        List<byte[]> messages = new ArrayList<>();
        new SnapshotCodec().write(original, (buffer, offset, length) -> {
            byte[] copy = new byte[length];
            buffer.getBytes(offset, copy);
            messages.add(copy);
        });
        // pretend the snapshot was written by schema version 1: header messages carry version 1
        for (byte[] m : messages) {
            new UnsafeBuffer(m).putShort(6, (short) 1, java.nio.ByteOrder.LITTLE_ENDIAN);
        }
        AccountingStateMachine restored = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(100));
        SnapshotCodec codec = new SnapshotCodec();
        messages.forEach(m -> codec.onMessage(restored, new UnsafeBuffer(m), 0, m.length));
        assertThat(codec.complete()).isTrue();
        assertThat(restored.digest()).isEqualTo(original.digest());
        assertThat(restored.export().count()).isZero();
    }
}
