/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import io.radiusward.protocol.ExactKeyChunkDecoder;
import io.radiusward.protocol.ExactKeyChunkEncoder;
import io.radiusward.protocol.MemberPositionChunkDecoder;
import io.radiusward.protocol.MemberPositionChunkEncoder;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.ReservationChunkDecoder;
import io.radiusward.protocol.ReservationChunkEncoder;
import io.radiusward.protocol.SessionChunkDecoder;
import io.radiusward.protocol.SessionChunkEncoder;
import io.radiusward.protocol.SessionStatus;
import io.radiusward.protocol.SinkChunkDecoder;
import io.radiusward.protocol.SinkChunkEncoder;
import io.radiusward.protocol.SnapshotFooterDecoder;
import io.radiusward.protocol.SnapshotFooterEncoder;
import io.radiusward.protocol.SnapshotHeaderDecoder;
import io.radiusward.protocol.SnapshotHeaderEncoder;
import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Streams the state machine into snapshot messages in chunks and rebuilds it from them. The format is the
 * SBE {@code SnapshotHeader}, {@code SessionChunk}*, {@code ExactKeyChunk}*, {@code SnapshotFooter}.
 */
public final class SnapshotCodec {

    /** Sessions per chunk: ~59 bytes each, so a chunk stays far below the snapshot channel's message limit. */
    static final int SESSIONS_PER_CHUNK = 256;

    static final int KEYS_PER_CHUNK = 1024;

    static final int RESERVATIONS_PER_CHUNK = 512;

    /** Receives encoded snapshot messages; must not return until the bytes are written. */
    @FunctionalInterface
    public interface Sink {
        void write(DirectBuffer buffer, int offset, int length);
    }

    /** Large enough for the largest chunk: a group header and its entries, plus room for a message header. */
    private final MutableDirectBuffer buffer = new UnsafeBuffer(
            new byte
                    [MessageHeaderEncoder.ENCODED_LENGTH
                            + 8
                            + Math.max(
                                    KEYS_PER_CHUNK * ExactKeyChunkEncoder.KeysEncoder.sbeBlockLength(),
                                    Math.max(
                                            SESSIONS_PER_CHUNK
                                                    * (SessionChunkEncoder.SessionsEncoder.sbeBlockLength()
                                                            + 4
                                                            + SessionStore.IDENTITY_SIZE),
                                            RESERVATIONS_PER_CHUNK
                                                    * ReservationChunkEncoder.ReservationsEncoder.sbeBlockLength()))
                            + 64]);

    private final ReservationChunkEncoder reservationChunkEncoder = new ReservationChunkEncoder();
    private final ReservationChunkDecoder reservationChunkDecoder = new ReservationChunkDecoder();
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final SnapshotHeaderEncoder snapshotHeaderEncoder = new SnapshotHeaderEncoder();
    private final SessionChunkEncoder sessionChunkEncoder = new SessionChunkEncoder();
    private final UnsafeBuffer identityScratch = new UnsafeBuffer(new byte[SessionStore.IDENTITY_SIZE]);
    private final ExactKeyChunkEncoder exactKeyChunkEncoder = new ExactKeyChunkEncoder();
    private final SnapshotFooterEncoder footerEncoder = new SnapshotFooterEncoder();
    private final SinkChunkEncoder sinkChunkEncoder = new SinkChunkEncoder();
    private final SinkChunkDecoder sinkChunkDecoder = new SinkChunkDecoder();
    private final MemberPositionChunkEncoder memberChunkEncoder = new MemberPositionChunkEncoder();
    private final MemberPositionChunkDecoder memberChunkDecoder = new MemberPositionChunkDecoder();
    private final byte[] nameBytes = new byte[ExportState.NAME_LENGTH];
    private final SnapshotHeaderDecoder snapshotHeaderDecoder = new SnapshotHeaderDecoder();
    private final SessionChunkDecoder sessionChunkDecoder = new SessionChunkDecoder();
    private final ExactKeyChunkDecoder exactKeyChunkDecoder = new ExactKeyChunkDecoder();
    private final SnapshotFooterDecoder footerDecoder = new SnapshotFooterDecoder();

    private long expectedSessions;
    private long expectedKeys;
    private long loadedSessions;
    private long loadedKeys;
    private long expectedSinks;
    private long loadedSinks;
    private long expectedMembers;
    private long loadedMembers;
    private long expectedReservations;
    private long loadedReservations;
    private boolean complete;

    // ---- writing -------------------------------------------------------------------------------

    public void write(AccountingStateMachine machine, Sink sink) {
        SessionStore store = machine.store();
        snapshotHeaderEncoder
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .stateVersion(AccountingStateMachine.STATE_VERSION)
                .applied(machine.applied())
                .duplicates(machine.duplicates())
                .stale(machine.stale())
                .rejected(machine.rejected())
                .stateDigest(machine.digest())
                .sessionCount(store.size())
                .exactKeyCount(machine.window().size())
                .timerScheduled((short) (machine.timerScheduled() ? 1 : 0))
                .sinkCount(machine.export().count())
                .lastCommandPosition(machine.export().lastCommandPosition())
                .memberPositionCount(reportedMembers(machine.export()))
                .activeVersion(machine.versions().activeRaw())
                .clusterSize(machine.versions().clusterSize())
                .reservationCount(machine.reservations().size());
        sink.write(buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + snapshotHeaderEncoder.encodedLength());

        int slot = 0;
        int end = store.highWater();
        while (slot < end) {
            int count = 0;
            for (int s = slot; s < end && count < SESSIONS_PER_CHUNK; s++) {
                if (store.state(s) != SessionStore.FREE) {
                    count++;
                }
            }
            if (count == 0) {
                break;
            }
            SessionChunkEncoder.SessionsEncoder sessions = sessionChunkEncoder
                    .wrapAndApplyHeader(buffer, 0, headerEncoder)
                    .sessionsCount(count);
            int written = 0;
            while (written < count) {
                if (store.state(slot) != SessionStore.FREE) {
                    sessions.next()
                            .keyHi(store.keyHi(slot))
                            .keyLo(store.keyLo(slot))
                            .nasId(store.nasId(slot))
                            .status(
                                    store.state(slot) == SessionStore.ACTIVE
                                            ? SessionStatus.ACTIVE
                                            : SessionStatus.STOPPED)
                            .statusType((short) store.statusType(slot))
                            .sessionTime(store.sessionTime(slot))
                            .eventTimestamp(store.eventTimestamp(slot))
                            .inputOctets(store.inputOctets(slot))
                            .outputOctets(store.outputOctets(slot))
                            .startKey(store.startKey(slot))
                            .lastSeen(store.lastSeen(slot))
                            .tombstoneUntil(store.tombstoneUntil(slot))
                            .flags((short) (store.flags(slot) & 0xFF))
                            .idleTimeoutMinutes(store.idleMinutes(slot))
                            .userKey(store.userKey(slot))
                            .deviceKey(store.deviceKey(slot))
                            .firstSeen(store.firstSeen(slot))
                            .putIdentity(identityScratch, 0, store.identity(slot, identityScratch, 0));
                    written++;
                }
                slot++;
            }
            sink.write(buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + sessionChunkEncoder.encodedLength());
        }

        long[] keys = new long[KEYS_PER_CHUNK];
        long[] expiries = new long[KEYS_PER_CHUNK];
        int[] n = {0};
        machine.window().forEach((key, expiry) -> {
            keys[n[0]] = key;
            expiries[n[0]] = expiry;
            if (++n[0] == KEYS_PER_CHUNK) {
                writeKeys(keys, expiries, n[0], sink);
                n[0] = 0;
            }
        });
        if (n[0] > 0) {
            writeKeys(keys, expiries, n[0], sink);
        }

        writeSinks(machine.export(), sink);
        writeMemberPositions(machine.export(), machine.versions(), sink);
        writeReservations(machine.reservations(), sink);

        footerEncoder
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .sessionCount(store.size())
                .exactKeyCount(machine.window().size());
        sink.write(buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + footerEncoder.encodedLength());
    }

    private static int reportedMembers(ExportState export) {
        int n = 0;
        for (int m = 0; m < ExportState.MAX_MEMBERS; m++) {
            if (export.memberReported(m)) {
                n++;
            }
        }
        return n;
    }

    private void writeMemberPositions(ExportState export, StateVersions versions, Sink sink) {
        int n = reportedMembers(export);
        if (n == 0) {
            return;
        }
        MemberPositionChunkEncoder.MembersEncoder members =
                memberChunkEncoder.wrapAndApplyHeader(buffer, 0, headerEncoder).membersCount(n);
        for (int m = 0; m < ExportState.MAX_MEMBERS; m++) {
            if (export.memberReported(m)) {
                members.next()
                        .memberId(m)
                        .logPosition(export.memberPosition(m))
                        .supportedVersion(versions.supported(m))
                        .hold((short) (versions.hold(m) ? 1 : 0));
            }
        }
        sink.write(buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + memberChunkEncoder.encodedLength());
    }

    private void writeSinks(ExportState export, Sink sink) {
        if (export.count() == 0) {
            return;
        }
        SinkChunkEncoder.SinksEncoder sinks =
                sinkChunkEncoder.wrapAndApplyHeader(buffer, 0, headerEncoder).sinksCount(export.count());
        for (int i = 0; i < export.count(); i++) {
            byte[] name = export.name(i).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            java.util.Arrays.fill(nameBytes, (byte) 0);
            System.arraycopy(name, 0, nameBytes, 0, Math.min(name.length, nameBytes.length));
            sinks.next()
                    .putName(nameBytes, 0)
                    .checkpoint(export.checkpoint(i))
                    .owner(export.owner(i))
                    .epoch(export.epoch(i))
                    .leaseExpiry(export.leaseExpiry(i))
                    .lastEventTime(export.lastEventTime(i))
                    .behindSince(export.behindSince(i))
                    .required((short) (export.required(i) ? 1 : 0))
                    .maxLagBytes(export.maxLagBytes(i))
                    .maxLagMs(export.maxLagMs(i))
                    .onMaxLag(
                            export.onMaxLag(i) == ExportState.ON_MAX_LAG_DETACH
                                    ? io.radiusward.protocol.OnMaxLag.DETACH
                                    : io.radiusward.protocol.OnMaxLag.BLOCK)
                    .detached((short) (export.detached(i) ? 1 : 0))
                    .resyncFrom(export.resyncFrom(i));
        }
        sink.write(buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + sinkChunkEncoder.encodedLength());
    }

    /** Only when there are reservations: they exist once state version 6 is active, so older code never sees one. */
    private void writeReservations(Reservations reservations, Sink sink) {
        int slot = 0;
        int end = reservations.highWater();
        while (slot < end) {
            int count = 0;
            for (int s = slot; s < end && count < RESERVATIONS_PER_CHUNK; s++) {
                if (reservations.used(s)) {
                    count++;
                }
            }
            if (count == 0) {
                return;
            }
            ReservationChunkEncoder.ReservationsEncoder group = reservationChunkEncoder
                    .wrapAndApplyHeader(buffer, 0, headerEncoder)
                    .reservationsCount(count);
            int written = 0;
            while (written < count) {
                if (reservations.used(slot)) {
                    group.next()
                            .userKey(reservations.user(slot))
                            .deviceKey(reservations.device(slot))
                            .expiry(reservations.expiry(slot));
                    written++;
                }
                slot++;
            }
            sink.write(buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + reservationChunkEncoder.encodedLength());
        }
    }

    private void writeKeys(long[] keys, long[] expiries, int count, Sink sink) {
        ExactKeyChunkEncoder.KeysEncoder group = exactKeyChunkEncoder
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .keysCount(count);
        for (int i = 0; i < count; i++) {
            group.next().key(keys[i]).expiry(expiries[i]);
        }
        sink.write(buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + exactKeyChunkEncoder.encodedLength());
    }

    // ---- reading -------------------------------------------------------------------------------

    /** Feeds one snapshot message into {@code machine}. */
    public void onMessage(AccountingStateMachine machine, DirectBuffer buffer, int offset, int length) {
        headerDecoder.wrap(buffer, offset);
        if (headerDecoder.schemaId() != MessageHeaderDecoder.SCHEMA_ID) {
            throw new IllegalStateException("unexpected schema " + headerDecoder.schemaId() + " in snapshot");
        }
        switch (headerDecoder.templateId()) {
            case SnapshotHeaderDecoder.TEMPLATE_ID -> {
                snapshotHeaderDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                // a snapshot written by newer code is fine as long as its active version is one this code knows
                // (a rollback before activation, ADR 0005)
                if (headerDecoder.version() >= 5) {
                    machine.versions()
                            .restore(snapshotHeaderDecoder.activeVersion(), snapshotHeaderDecoder.clusterSize());
                }
                machine.versions().requireSupported();
                machine.restoreCounters(
                        snapshotHeaderDecoder.applied(),
                        snapshotHeaderDecoder.duplicates(),
                        snapshotHeaderDecoder.stale(),
                        snapshotHeaderDecoder.rejected(),
                        snapshotHeaderDecoder.stateDigest(),
                        snapshotHeaderDecoder.timerScheduled() != 0);
                expectedSessions = snapshotHeaderDecoder.sessionCount();
                expectedKeys = snapshotHeaderDecoder.exactKeyCount();
                if (headerDecoder.version() >= 2) {
                    expectedSinks = snapshotHeaderDecoder.sinkCount();
                    expectedMembers = snapshotHeaderDecoder.memberPositionCount();
                    machine.export().restoreLastCommandPosition(snapshotHeaderDecoder.lastCommandPosition());
                }
                if (headerDecoder.version() >= 6) {
                    expectedReservations = snapshotHeaderDecoder.reservationCount();
                }
            }
            case SessionChunkDecoder.TEMPLATE_ID -> {
                sessionChunkDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                for (SessionChunkDecoder.SessionsDecoder s : sessionChunkDecoder.sessions()) {
                    machine.restoreSession(
                            s.keyHi(),
                            s.keyLo(),
                            s.nasId(),
                            s.status() == SessionStatus.ACTIVE ? SessionStore.ACTIVE : SessionStore.STOPPED,
                            s.statusType(),
                            s.flags(),
                            s.sessionTime(),
                            s.eventTimestamp(),
                            s.inputOctets(),
                            s.outputOctets(),
                            s.startKey(),
                            s.lastSeen(),
                            s.tombstoneUntil(),
                            sessionChunkDecoder.actingVersion() >= 4 ? s.idleTimeoutMinutes() : 0);
                    if (sessionChunkDecoder.actingVersion() >= 6) {
                        machine.restoreUser(s.keyHi(), s.keyLo(), s.userKey(), s.deviceKey());
                    }
                    if (sessionChunkDecoder.actingVersion() >= 7) {
                        int identity = s.getIdentity(
                                identityScratch, 0, Math.min(s.identityLength(), SessionStore.IDENTITY_SIZE - 1));
                        machine.restoreIdentity(s.keyHi(), s.keyLo(), s.firstSeen(), identityScratch, 0, identity);
                    }
                    loadedSessions++;
                }
            }
            case ExactKeyChunkDecoder.TEMPLATE_ID -> {
                exactKeyChunkDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                for (ExactKeyChunkDecoder.KeysDecoder k : exactKeyChunkDecoder.keys()) {
                    machine.restoreExactKey(k.key(), k.expiry());
                    loadedKeys++;
                }
            }
            case SinkChunkDecoder.TEMPLATE_ID -> {
                sinkChunkDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                for (SinkChunkDecoder.SinksDecoder s : sinkChunkDecoder.sinks()) {
                    int nameLength = s.getName(nameBytes, 0);
                    int end = 0;
                    while (end < nameLength && nameBytes[end] != 0) {
                        end++;
                    }
                    machine.export()
                            .restore(
                                    new String(nameBytes, 0, end, java.nio.charset.StandardCharsets.US_ASCII),
                                    s.checkpoint(),
                                    s.owner(),
                                    s.epoch(),
                                    s.leaseExpiry(),
                                    s.lastEventTime(),
                                    s.behindSince(),
                                    s.required() != 0,
                                    s.maxLagBytes(),
                                    s.maxLagMs(),
                                    s.onMaxLag() == io.radiusward.protocol.OnMaxLag.DETACH
                                            ? ExportState.ON_MAX_LAG_DETACH
                                            : ExportState.ON_MAX_LAG_BLOCK,
                                    s.detached() != 0,
                                    s.resyncFrom());
                    loadedSinks++;
                }
            }
            case MemberPositionChunkDecoder.TEMPLATE_ID -> {
                memberChunkDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                for (MemberPositionChunkDecoder.MembersDecoder m : memberChunkDecoder.members()) {
                    machine.export().memberPosition(m.memberId(), m.logPosition());
                    if (memberChunkDecoder.actingVersion() >= 5) {
                        machine.versions().restoreMember(m.memberId(), m.supportedVersion(), m.hold() != 0);
                    }
                    loadedMembers++;
                }
            }
            case ReservationChunkDecoder.TEMPLATE_ID -> {
                reservationChunkDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                for (ReservationChunkDecoder.ReservationsDecoder r : reservationChunkDecoder.reservations()) {
                    machine.restoreReservation(r.userKey(), r.deviceKey(), r.expiry());
                    loadedReservations++;
                }
            }
            case SnapshotFooterDecoder.TEMPLATE_ID -> {
                footerDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                if (loadedSessions != expectedSessions
                        || loadedKeys != expectedKeys
                        || loadedSinks != expectedSinks
                        || loadedMembers != expectedMembers
                        || loadedReservations != expectedReservations) {
                    throw new IllegalStateException("snapshot incomplete: sessions " + loadedSessions + "/"
                            + expectedSessions + ", keys " + loadedKeys + "/" + expectedKeys + ", sinks "
                            + loadedSinks + "/" + expectedSinks + ", reservations " + loadedReservations + "/"
                            + expectedReservations);
                }
                complete = true;
            }
            default ->
                throw new IllegalStateException("unexpected template " + headerDecoder.templateId() + " in snapshot");
        }
    }

    /** Whether the footer has been read and the counts matched. */
    public boolean complete() {
        return complete;
    }
}
