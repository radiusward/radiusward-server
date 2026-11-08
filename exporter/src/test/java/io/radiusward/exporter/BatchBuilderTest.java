/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.SessionSnapshot;
import io.radiusward.protocol.AccountingCommandEncoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import java.util.UUID;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class BatchBuilderTest {

    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[1024]);
    private long position;

    private void command(StateMachineReplica replica, long session, int status, long sessionTime, long now) {
        AccountingCommandEncoder e = new AccountingCommandEncoder()
                .wrapAndApplyHeader(buffer, 0, new MessageHeaderEncoder())
                .correlationId(session)
                .gatewayId(1)
                .nasId(7)
                .sessionKeyHi(session)
                .sessionKeyLo(session)
                .exactKeyHi(session * 31 + status)
                .exactKeyLo(sessionTime)
                .statusType(status)
                .sessionTime(sessionTime)
                .inputOctets(sessionTime * 10)
                .outputOctets(sessionTime * 20);
        e.flags().clear().sessionTimePresent(status != AccountingStateMachine.STATUS_START);
        e.sessionId("s" + session);
        e.putRawAttributes(new byte[] {1, 3, 'x'}, 0, 3);
        position += 128;
        replica.onSessionMessage(position, now, buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + e.encodedLength());
    }

    private StateMachineReplica replica(BatchBuilder builder, long start) {
        StateMachineReplica replica =
                StateMachineReplica.empty(AccountingStateMachine.Settings.defaults(1_000), builder);
        builder.attach(replica, start);
        return replica;
    }

    @Test
    void appliedEventsAndLatestSessionPerKey() {
        BatchBuilder builder = new BatchBuilder("pg", true);
        StateMachineReplica replica = replica(builder, 0);
        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 1_000);
        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 60, 61_000);
        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 60, 62_000); // duplicate
        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 30, 63_000); // stale
        command(replica, 2, AccountingStateMachine.STATUS_START, 0, 64_000);
        command(replica, 1, AccountingStateMachine.STATUS_STOP, 90, 91_000);

        Batch batch = builder.take(3);
        assertThat(batch.epoch()).isEqualTo(3);
        assertThat(batch.fromPosition()).isZero();
        assertThat(batch.toPosition()).isEqualTo(position);
        assertThat(batch.events())
                .extracting(ExportEvent::outcome)
                .containsExactly(
                        ExportEvent.EventOutcome.APPLIED,
                        ExportEvent.EventOutcome.APPLIED,
                        ExportEvent.EventOutcome.STALE,
                        ExportEvent.EventOutcome.APPLIED,
                        ExportEvent.EventOutcome.APPLIED);
        assertThat(batch.events().get(0).acctSessionId()).isEqualTo("s1");
        assertThat(batch.events().get(0).sessionTime()).isNull();
        assertThat(batch.events().get(0).rawAttributes()).containsExactly(1, 3, 'x');

        assertThat(batch.sessions()).hasSize(2);
        SessionSnapshot s1 = batch.sessions().stream()
                .filter(s -> s.sessionKey().equals(new UUID(1, 1)))
                .findFirst()
                .orElseThrow();
        assertThat(s1.state()).isEqualTo(SessionSnapshot.State.STOPPED);
        assertThat(s1.closeCause()).isEqualTo(SessionSnapshot.CloseCause.STOP);
        assertThat(s1.sessionTime()).isEqualTo(90);
        assertThat(s1.stoppedAt()).isEqualTo(91_000);
        assertThat(s1.projectionVersion()).isEqualTo(position);
        assertThat(builder.rows()).isZero();
    }

    @Test
    void accountingOnClosesTheNasSessions() {
        BatchBuilder builder = new BatchBuilder("pg", false);
        StateMachineReplica replica = replica(builder, 0);
        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 1_000);
        command(replica, 2, AccountingStateMachine.STATUS_START, 0, 1_000);
        builder.take(1);
        command(replica, 99, AccountingStateMachine.STATUS_ACCOUNTING_ON, 0, 5_000);

        Batch batch = builder.take(1);
        assertThat(batch.events()).as("mode sessions keeps no events").isEmpty();
        assertThat(batch.sessions()).hasSize(2).allSatisfy(s -> {
            assertThat(s.state()).isEqualTo(SessionSnapshot.State.STOPPED);
            assertThat(s.closeCause()).isEqualTo(SessionSnapshot.CloseCause.NAS_RESTART);
            assertThat(s.stoppedAt()).isEqualTo(5_000);
            assertThat(s.acctSessionId()).isNull();
        });
    }

    @Test
    void nothingAtOrBelowTheStartPositionIsExportedAgain() {
        BatchBuilder builder = new BatchBuilder("pg", true);
        StateMachineReplica replica = replica(builder, 256);
        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 1_000); // 128
        command(replica, 2, AccountingStateMachine.STATUS_START, 0, 1_000); // 256
        assertThat(builder.rows()).isZero();
        assertThat(builder.hasProgress()).isFalse();
        command(replica, 3, AccountingStateMachine.STATUS_START, 0, 1_000); // 384
        Batch batch = builder.take(1);
        assertThat(batch.fromPosition()).isEqualTo(256);
        assertThat(batch.events()).hasSize(1);
        assertThat(batch.events().get(0).acctSessionId()).isEqualTo("s3");
    }
}
