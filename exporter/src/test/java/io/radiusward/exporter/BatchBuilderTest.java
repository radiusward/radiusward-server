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
        command(replica, session, status, sessionTime, 0, now);
    }

    /** {@code eventTimestamp} in seconds, 0 for none. */
    private void command(
            StateMachineReplica replica, long session, int status, long sessionTime, long eventTimestamp, long now) {
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
                .eventTimestamp(eventTimestamp)
                .inputOctets(sessionTime * 10)
                .outputOctets(sessionTime * 20);
        e.flags()
                .clear()
                .sessionTimePresent(status != AccountingStateMachine.STATUS_START)
                .eventTimestampPresent(eventTimestamp != 0);
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

    private static SessionSnapshot session(Batch batch, long session) {
        return batch.sessions().stream()
                .filter(s -> s.sessionKey().equals(new UUID(session, session)))
                .findFirst()
                .orElseThrow();
    }

    @Test
    void startTimeIsTheEventTimestampOfTheStartOrItsCommitTime() {
        BatchBuilder builder = new BatchBuilder("pg", false);
        StateMachineReplica replica = replica(builder, 0);
        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 1_780_000_000L, 1_780_000_002_500L);
        command(replica, 2, AccountingStateMachine.STATUS_START, 0, 0, 1_780_000_003_000L);
        Batch batch = builder.take(1);
        assertThat(session(batch, 1).startedAt()).isEqualTo(1_780_000_000_000L);
        assertThat(session(batch, 2).startedAt()).as("no Event-Timestamp").isEqualTo(1_780_000_003_000L);
    }

    @Test
    void interimWithoutStartCreatesTheSessionWithADerivedStartTime() {
        BatchBuilder builder = new BatchBuilder("pg", true);
        StateMachineReplica replica = replica(builder, 0);
        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 300, 1_780_000_300L, 1_780_000_301_000L);
        command(replica, 2, AccountingStateMachine.STATUS_INTERIM, 60, 0, 1_780_000_090_000L);
        Batch batch = builder.take(1);
        assertThat(batch.events()).extracting(ExportEvent::outcome).containsOnly(ExportEvent.EventOutcome.APPLIED);
        SessionSnapshot s1 = session(batch, 1);
        assertThat(s1.state()).isEqualTo(SessionSnapshot.State.ACTIVE);
        assertThat(s1.sessionTime()).isEqualTo(300);
        assertThat(s1.inputOctets()).isEqualTo(3000);
        assertThat(s1.startedAt()).as("event time minus session time").isEqualTo(1_780_000_000_000L);
        assertThat(session(batch, 2).startedAt())
                .as("commit time minus session time")
                .isEqualTo(1_780_000_030_000L);

        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 600, 1_780_000_600L, 1_780_000_601_000L);
        assertThat(session(builder.take(1), 1).startedAt())
                .as("later interims leave the start time alone")
                .isNull();
    }

    @Test
    void lateStartIsMergedKeepingTheProgressAndSettingTheStartTime() {
        BatchBuilder builder = new BatchBuilder("pg", true);
        StateMachineReplica replica = replica(builder, 0);
        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 300, 1_780_000_300L, 1_780_000_301_000L);
        builder.take(1);
        // the Start reached the cluster only now; the NAS stamped it 2 s later than the interim implies
        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 1_780_000_002L, 1_780_000_305_000L);

        Batch batch = builder.take(1);
        assertThat(batch.events()).singleElement().satisfies(e -> {
            assertThat(e.statusType()).isEqualTo(AccountingStateMachine.STATUS_START);
            assertThat(e.outcome()).isEqualTo(ExportEvent.EventOutcome.MERGED);
        });
        SessionSnapshot s = session(batch, 1);
        assertThat(s.state()).isEqualTo(SessionSnapshot.State.ACTIVE);
        assertThat(s.statusType()).as("still the interim's progress").isEqualTo(AccountingStateMachine.STATUS_INTERIM);
        assertThat(s.sessionTime()).isEqualTo(300);
        assertThat(s.inputOctets()).isEqualTo(3000);
        assertThat(s.outputOctets()).isEqualTo(6000);
        assertThat(s.startedAt()).as("the Start's own time wins").isEqualTo(1_780_000_002_000L);
        assertThat(s.lastReceivedAt()).isEqualTo(1_780_000_305_000L);
        assertThat(s.acctSessionId()).isEqualTo("s1");
        assertThat(s.projectionVersion()).isEqualTo(position);

        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 1_780_000_002L, 1_780_000_306_000L);
        assertThat(builder.rows()).as("its retransmission is a duplicate").isZero();
    }

    @Test
    void lateStartWithoutEventTimestampKeepsTheDerivedStartTime() {
        BatchBuilder builder = new BatchBuilder("pg", false);
        StateMachineReplica replica = replica(builder, 0);
        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 60, 0, 61_000);
        builder.take(1);
        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 0, 62_000);
        SessionSnapshot s = session(builder.take(1), 1);
        assertThat(s.startedAt())
                .as("its commit time would be later than the real start")
                .isNull();
        assertThat(s.sessionTime()).isEqualTo(60);
    }

    @Test
    void lateStartAfterStopIsStaleHistoryOnly() {
        BatchBuilder builder = new BatchBuilder("pg", true);
        StateMachineReplica replica = replica(builder, 0);
        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 300, 1_780_000_300L, 301_000);
        command(replica, 1, AccountingStateMachine.STATUS_STOP, 600, 1_780_000_600L, 601_000);
        builder.take(1);
        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 1_780_000_000L, 602_000);
        Batch batch = builder.take(1);
        assertThat(batch.events()).extracting(ExportEvent::outcome).containsExactly(ExportEvent.EventOutcome.STALE);
        assertThat(batch.sessions()).as("the closed session is not touched").isEmpty();
    }

    @Test
    void startTimeIsCarriedToTheLatestSnapshotOfABatch() {
        BatchBuilder builder = new BatchBuilder("pg", false);
        StateMachineReplica replica = replica(builder, 0);
        command(replica, 1, AccountingStateMachine.STATUS_START, 0, 1_780_000_000L, 1_000);
        command(replica, 1, AccountingStateMachine.STATUS_INTERIM, 60, 1_780_000_060L, 61_000);
        command(replica, 2, AccountingStateMachine.STATUS_START, 0, 1_780_000_000L, 1_000);
        command(replica, 99, AccountingStateMachine.STATUS_ACCOUNTING_ON, 0, 0, 70_000);
        Batch batch = builder.take(1);
        assertThat(session(batch, 1).statusType()).isEqualTo(AccountingStateMachine.STATUS_INTERIM);
        assertThat(session(batch, 1).startedAt()).isEqualTo(1_780_000_000_000L);
        assertThat(session(batch, 2).closeCause()).isEqualTo(SessionSnapshot.CloseCause.NAS_RESTART);
        assertThat(session(batch, 2).startedAt()).isEqualTo(1_780_000_000_000L);
    }
}
