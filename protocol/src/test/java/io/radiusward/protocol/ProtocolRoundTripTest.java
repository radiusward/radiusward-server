/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.protocol;

import static org.assertj.core.api.Assertions.assertThat;

import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class ProtocolRoundTripTest {

    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[4096]);
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();

    private static final byte[] RAW = {40, 6, 0, 0, 0, 1};

    private int encodeCommand() {
        AccountingCommandEncoder encoder = new AccountingCommandEncoder();
        encoder.wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(42L)
                .gatewayId(7)
                .nasId(1001)
                .sessionKeyHi(0x1122334455667788L)
                .sessionKeyLo(-1L)
                .exactKeyHi(5L)
                .exactKeyLo(6L)
                .statusType(3L)
                .sessionTime(300L)
                .eventTimestamp(1_780_000_000L)
                .inputOctets(13_958_643_712L)
                .outputOctets(1L)
                .nasClientId(1000)
                .identityFingerprint(-7);
        encoder.flags()
                .clear()
                .sessionTimePresent(true)
                .eventTimestampPresent(true)
                .sessionIdPresent(true)
                .deviceUnknown(false);
        encoder.sessionId("00000A1B");
        encoder.putRawAttributes(RAW, 0, RAW.length);
        encoder.nasDevice("ap-17");
        return MessageHeaderEncoder.ENCODED_LENGTH + encoder.encodedLength();
    }

    @Test
    void accountingCommand() {
        int length = encodeCommand();
        headerDecoder.wrap(buffer, 0);
        assertThat(headerDecoder.schemaId()).isEqualTo(AccountingCommandDecoder.SCHEMA_ID);
        assertThat(headerDecoder.templateId()).isEqualTo(AccountingCommandDecoder.TEMPLATE_ID);

        AccountingCommandDecoder d = new AccountingCommandDecoder().wrapAndApplyHeader(buffer, 0, headerDecoder);
        assertThat(d.correlationId()).isEqualTo(42L);
        assertThat(d.gatewayId()).isEqualTo(7);
        assertThat(d.nasId()).isEqualTo(1001);
        assertThat(d.sessionKeyHi()).isEqualTo(0x1122334455667788L);
        assertThat(d.sessionKeyLo()).isEqualTo(-1L);
        assertThat(d.exactKeyHi()).isEqualTo(5L);
        assertThat(d.exactKeyLo()).isEqualTo(6L);
        assertThat(d.statusType()).isEqualTo(3L);
        assertThat(d.flags().sessionTimePresent()).isTrue();
        assertThat(d.flags().eventTimestampPresent()).isTrue();
        assertThat(d.sessionTime()).isEqualTo(300L);
        assertThat(d.eventTimestamp()).isEqualTo(1_780_000_000L);
        assertThat(d.inputOctets()).isEqualTo(13_958_643_712L);
        assertThat(d.outputOctets()).isEqualTo(1L);
        assertThat(d.sessionId()).isEqualTo("00000A1B");
        byte[] raw = new byte[d.rawAttributesLength()];
        d.getRawAttributes(raw, 0, raw.length);
        assertThat(raw).containsExactly(RAW);
        assertThat(d.nasClientId()).isEqualTo(1000);
        assertThat(d.identityFingerprint()).isEqualTo(-7);
        assertThat(d.flags().deviceUnknown()).isFalse();
        assertThat(d.nasDevice()).isEqualTo("ap-17");
        assertThat(MessageHeaderDecoder.ENCODED_LENGTH + d.encodedLength()).isEqualTo(length);
    }

    @Test
    void committedAndRejected() {
        new AccountingCommittedEncoder()
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(9L)
                .outcome(Outcome.DUPLICATE)
                .eventId(123_456L);
        AccountingCommittedDecoder committed =
                new AccountingCommittedDecoder().wrapAndApplyHeader(buffer, 0, headerDecoder);
        assertThat(committed.correlationId()).isEqualTo(9L);
        assertThat(committed.outcome()).isEqualTo(Outcome.DUPLICATE);
        assertThat(committed.eventId()).isEqualTo(123_456L);

        new AccountingRejectedEncoder()
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(10L)
                .reason(RejectReason.CAPACITY);
        AccountingRejectedDecoder rejected =
                new AccountingRejectedDecoder().wrapAndApplyHeader(buffer, 0, headerDecoder);
        assertThat(rejected.reason()).isEqualTo(RejectReason.CAPACITY);
    }

    @Test
    void queriesAndReports() {
        new SessionQueryEncoder()
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(1)
                .sessionKeyHi(2)
                .sessionKeyLo(3);
        SessionQueryDecoder sq = new SessionQueryDecoder().wrapAndApplyHeader(buffer, 0, headerDecoder);
        assertThat(sq.sessionKeyLo()).isEqualTo(3);

        new SessionReportEncoder()
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(1)
                .status(SessionStatus.ACTIVE)
                .nasId(5)
                .statusType(3)
                .sessionTime(60)
                .eventTimestamp(70)
                .inputOctets(80)
                .outputOctets(90);
        SessionReportDecoder sr = new SessionReportDecoder().wrapAndApplyHeader(buffer, 0, headerDecoder);
        assertThat(sr.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(sr.outputOctets()).isEqualTo(90);

        new StateQueryEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(4);
        assertThat(new StateQueryDecoder()
                        .wrapAndApplyHeader(buffer, 0, headerDecoder)
                        .correlationId())
                .isEqualTo(4);

        new StateReportEncoder()
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(4)
                .applied(10)
                .duplicates(2)
                .stale(1)
                .rejected(0)
                .activeSessions(7)
                .stoppedSessions(3)
                .stateDigest(-5)
                .stateVersion(1);
        StateReportDecoder report = new StateReportDecoder().wrapAndApplyHeader(buffer, 0, headerDecoder);
        assertThat(report.applied()).isEqualTo(10);
        assertThat(report.stateDigest()).isEqualTo(-5);
        assertThat(report.stateVersion()).isEqualTo(1);
    }

    @Test
    void snapshotMessages() {
        SessionChunkEncoder chunk = new SessionChunkEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder);
        SessionChunkEncoder.SessionsEncoder sessions = chunk.sessionsCount(2);
        for (int i = 0; i < 2; i++) {
            sessions.next()
                    .keyHi(i)
                    .keyLo(i + 10)
                    .nasId(i + 20)
                    .status(SessionStatus.STOPPED)
                    .statusType((short) 2)
                    .sessionTime(100 + i)
                    .eventTimestamp(200 + i)
                    .inputOctets(300 + i)
                    .outputOctets(400 + i)
                    .startKey(500 + i)
                    .lastSeen(600 + i)
                    .tombstoneUntil(700 + i);
        }
        SessionChunkDecoder decoded = new SessionChunkDecoder().wrapAndApplyHeader(buffer, 0, headerDecoder);
        int n = 0;
        for (SessionChunkDecoder.SessionsDecoder s : decoded.sessions()) {
            assertThat(s.keyLo()).isEqualTo(n + 10);
            assertThat(s.tombstoneUntil()).isEqualTo(700 + n);
            n++;
        }
        assertThat(n).isEqualTo(2);

        ExactKeyChunkEncoder keys = new ExactKeyChunkEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder);
        keys.keysCount(1).next().key(77).expiry(88);
        ExactKeyChunkDecoder.KeysDecoder decodedKeys = new ExactKeyChunkDecoder()
                .wrapAndApplyHeader(buffer, 0, headerDecoder)
                .keys();
        assertThat(decodedKeys.next().key()).isEqualTo(77);

        new SnapshotHeaderEncoder()
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .stateVersion(1)
                .sessionCount(2)
                .exactKeyCount(1)
                .timerScheduled((short) 1);
        assertThat(new SnapshotHeaderDecoder()
                        .wrapAndApplyHeader(buffer, 0, headerDecoder)
                        .sessionCount())
                .isEqualTo(2);
        new SnapshotFooterEncoder()
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .sessionCount(2)
                .exactKeyCount(1);
        assertThat(new SnapshotFooterDecoder()
                        .wrapAndApplyHeader(buffer, 0, headerDecoder)
                        .exactKeyCount())
                .isEqualTo(1);
    }

    /** A decoder must read a message written by a later schema version (fields are only appended). */
    @Test
    void decoderReadsMessageOfALaterVersion() {
        io.radiusward.protocol.v2test.MessageHeaderEncoder v2Header =
                new io.radiusward.protocol.v2test.MessageHeaderEncoder();
        io.radiusward.protocol.v2test.AccountingCommandEncoder v2 =
                new io.radiusward.protocol.v2test.AccountingCommandEncoder();
        v2.wrapAndApplyHeader(buffer, 0, v2Header)
                .correlationId(99L)
                .nasId(3)
                .statusType(2L)
                .outputOctets(55L)
                .futureField(123L);
        v2.sessionId("abc");
        v2.putRawAttributes(RAW, 0, RAW.length);

        headerDecoder.wrap(buffer, 0);
        assertThat(headerDecoder.version()).isEqualTo(4);
        AccountingCommandDecoder v1 = new AccountingCommandDecoder().wrapAndApplyHeader(buffer, 0, headerDecoder);
        assertThat(v1.correlationId()).isEqualTo(99L);
        assertThat(v1.nasId()).isEqualTo(3);
        assertThat(v1.outputOctets()).isEqualTo(55L);
        assertThat(v1.sessionId()).isEqualTo("abc");
        assertThat(v1.rawAttributesLength()).isEqualTo(RAW.length);
    }
}
