/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.protocol.AccountingCommandEncoder;
import io.radiusward.protocol.ExportCheckpointEncoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.OnMaxLag;
import io.radiusward.protocol.StateQueryEncoder;
import java.nio.charset.StandardCharsets;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class LogApplierTest {

    private final AccountingStateMachine machine =
            new AccountingStateMachine(AccountingStateMachine.Settings.defaults(1_000));
    private final LogApplier applier = new LogApplier(machine);
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
    private final MessageHeaderEncoder header = new MessageHeaderEncoder();

    private int command(long session, long position, long now) {
        new AccountingCommandEncoder()
                .wrapAndApplyHeader(buffer, 0, header)
                .correlationId(session)
                .nasId(1)
                .sessionKeyHi(session)
                .sessionKeyLo(session)
                .exactKeyHi(session)
                .exactKeyLo(session)
                .statusType(AccountingStateMachine.STATUS_START);
        return applier.apply(buffer, 0, position, now);
    }

    private int checkpoint(long position, long maxLagBytes, long now) {
        byte[] name = new byte[ExportState.NAME_LENGTH];
        System.arraycopy("pg".getBytes(StandardCharsets.US_ASCII), 0, name, 0, 2);
        new ExportCheckpointEncoder()
                .wrapAndApplyHeader(buffer, 0, header)
                .correlationId(7)
                .putSinkName(name, 0)
                .memberId(0)
                .epoch(machine.export().count() == 0 ? 0 : machine.export().epoch(0))
                .position(position)
                .lastEventTime(now)
                .leaseTimeoutMs(10_000)
                .required((short) 1)
                .maxLagBytes(maxLagBytes)
                .maxLagMs(0)
                .onMaxLag(OnMaxLag.BLOCK);
        return applier.apply(buffer, 0, position, now);
    }

    @Test
    void commandsCheckpointsAndBlocking() {
        assertThat(command(1, 100, 1)).isEqualTo(Outcomes.APPLIED);
        assertThat(checkpoint(0, 150, 2)).isEqualTo(LogApplier.CHECKPOINT);
        assertThat(applier.leaseResult()).isEqualTo(ExportState.GRANTED);
        assertThat(applier.sinkSlot()).isZero();

        assertThat(command(2, 140, 3)).isEqualTo(Outcomes.APPLIED);
        assertThat(command(3, 200, 4)).as("200 bytes behind, limit 150").isEqualTo(Outcomes.REJECTED_EXPORT_LAG);
        assertThat(machine.rejected()).isEqualTo(1);

        checkpoint(200, 150, 5);
        assertThat(command(3, 260, 6)).isEqualTo(Outcomes.APPLIED);
        assertThat(machine.applied()).isEqualTo(3);
    }

    @Test
    void queriesChangeNothing() {
        new StateQueryEncoder().wrapAndApplyHeader(buffer, 0, header).correlationId(1);
        assertThat(applier.apply(buffer, 0, 100, 1)).isEqualTo(LogApplier.NOT_A_COMMAND);
        assertThat(applier.claimSweepTimer()).isTrue();
        assertThat(applier.claimSweepTimer()).isFalse();
        assertThat(applier.onTimer(99, 1)).isFalse();
        assertThat(applier.onTimer(LogApplier.SWEEP_TIMER_ID, 1)).isTrue();
    }
}
