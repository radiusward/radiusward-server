/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import io.aeron.ExclusivePublication;
import io.aeron.Image;
import io.aeron.Publication;
import io.aeron.cluster.codecs.CloseReason;
import io.aeron.cluster.service.ClientSession;
import io.aeron.cluster.service.Cluster;
import io.aeron.cluster.service.ClusteredService;
import io.aeron.logbuffer.FragmentHandler;
import io.aeron.logbuffer.Header;
import io.radiusward.protocol.AccountingCommittedEncoder;
import io.radiusward.protocol.AccountingRejectedEncoder;
import io.radiusward.protocol.ExportCheckpointAckEncoder;
import io.radiusward.protocol.ExportCheckpointDecoder;
import io.radiusward.protocol.LeaseResult;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.Outcome;
import io.radiusward.protocol.RejectReason;
import io.radiusward.protocol.SessionQueryDecoder;
import io.radiusward.protocol.SessionReportEncoder;
import io.radiusward.protocol.SessionStatus;
import io.radiusward.protocol.StateQueryDecoder;
import io.radiusward.protocol.StateReportEncoder;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.IdleStrategy;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The clustered service: decodes commands from the replicated log, applies them to the
 * {@link AccountingStateMachine} and answers the gateway over egress. Only the leader's replies leave the
 * node (Aeron mocks egress on followers). Uses cluster time only; every state change happens in
 * {@link #onSessionMessage} or {@link #onTimerEvent}, so all replicas stay identical.
 */
public final class AccountingService implements ClusteredService {

    private static final Logger LOG = LogManager.getLogger(AccountingService.class);

    private static final int MAX_EGRESS_ATTEMPTS = 3;

    private final AccountingStateMachine machine;
    private final LogApplier applier;
    private final long sweepIntervalMs;
    private final ServiceStats stats = new ServiceStats();
    /** Identity setting per NAS entry as first seen (ADR 0019); not replicated state, only for the mismatch counter. */
    private final org.agrona.collections.Int2IntHashMap identityByNas =
            new org.agrona.collections.Int2IntHashMap(Integer.MIN_VALUE);

    private final SnapshotCodec snapshotCodec = new SnapshotCodec();

    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final SessionQueryDecoder sessionQueryDecoder = new SessionQueryDecoder();
    private final StateQueryDecoder stateQueryDecoder = new StateQueryDecoder();
    private final AccountingCommittedEncoder committedEncoder = new AccountingCommittedEncoder();
    private final AccountingRejectedEncoder rejectedEncoder = new AccountingRejectedEncoder();
    private final SessionReportEncoder sessionReportEncoder = new SessionReportEncoder();
    private final StateReportEncoder stateReportEncoder = new StateReportEncoder();
    private final io.radiusward.protocol.ActivateVersionResultEncoder activationEncoder =
            new io.radiusward.protocol.ActivateVersionResultEncoder();
    private final io.radiusward.protocol.SqnResultEncoder sqnEncoder = new io.radiusward.protocol.SqnResultEncoder();
    private final io.radiusward.protocol.AuthReservationResultEncoder reservationEncoder =
            new io.radiusward.protocol.AuthReservationResultEncoder();
    private boolean holdWarned;
    private final ExportCheckpointAckEncoder checkpointAckEncoder = new ExportCheckpointAckEncoder();
    private final io.radiusward.protocol.SinkQueryDecoder sinkQueryDecoder =
            new io.radiusward.protocol.SinkQueryDecoder();
    private final io.radiusward.protocol.SinkReportEncoder sinkReportEncoder =
            new io.radiusward.protocol.SinkReportEncoder();
    private final UnsafeBuffer sinkBuffer = new UnsafeBuffer(new byte[4096]);
    private final UnsafeBuffer egressBuffer = new UnsafeBuffer(new byte[512]);
    /** Reports with lists of sessions (ADR 0036): at most {@link #MAX_LISTED} entries of up to 160 bytes. */
    private final UnsafeBuffer listBuffer = new UnsafeBuffer(new byte[MAX_LISTED * 160 + 64]);

    private final UnsafeBuffer identityScratch = new UnsafeBuffer(new byte[SessionStore.IDENTITY_SIZE]);
    private final io.radiusward.protocol.UserSessionsQueryDecoder userSessionsQueryDecoder =
            new io.radiusward.protocol.UserSessionsQueryDecoder();
    private final io.radiusward.protocol.UserSessionsReportEncoder userSessionsReportEncoder =
            new io.radiusward.protocol.UserSessionsReportEncoder();
    private final io.radiusward.protocol.SessionPageQueryDecoder sessionPageQueryDecoder =
            new io.radiusward.protocol.SessionPageQueryDecoder();
    private final io.radiusward.protocol.SessionPageReportEncoder sessionPageReportEncoder =
            new io.radiusward.protocol.SessionPageReportEncoder();
    static final int MAX_LISTED = 64;

    private Cluster cluster;
    private IdleStrategy idleStrategy;

    public AccountingService(AccountingStateMachine.Settings settings, long sweepIntervalMs) {
        this.machine = new AccountingStateMachine(settings);
        this.applier = new LogApplier(machine);
        this.sweepIntervalMs = sweepIntervalMs;
    }

    /** Counters published for the management server; safe to read from any thread. */
    public ServiceStats stats() {
        return stats;
    }

    @Override
    public void onStart(Cluster cluster, Image snapshotImage) {
        this.cluster = cluster;
        this.idleStrategy = cluster.idleStrategy();
        if (snapshotImage != null) {
            loadSnapshot(snapshotImage);
            LOG.info(
                    "restored snapshot: {} sessions, {} applied, digest {}",
                    machine.store().size(),
                    machine.applied(),
                    Long.toHexString(machine.digest()));
        }
        stats.memberId(cluster.memberId());
        stats.role(cluster.role().name()); // onRoleChange only fires on a change, followers would stay unknown
        publishStats(0);
    }

    private void loadSnapshot(Image image) {
        FragmentHandler handler =
                (buffer, offset, length, header) -> snapshotCodec.onMessage(machine, buffer, offset, length);
        io.aeron.FragmentAssembler assembler = new io.aeron.FragmentAssembler(handler);
        while (!snapshotCodec.complete()) {
            int fragments = image.poll(assembler, 16);
            if (fragments == 0) {
                if (image.isClosed() || image.isEndOfStream()) {
                    if (!snapshotCodec.complete()) {
                        throw new IllegalStateException("snapshot ended before its footer");
                    }
                    break;
                }
                idleStrategy.idle();
            }
        }
    }

    @Override
    public void onSessionOpen(ClientSession session, long timestamp) {
        LOG.info("cluster session {} opened", session.id());
    }

    @Override
    public void onSessionClose(ClientSession session, long timestamp, CloseReason closeReason) {
        LOG.info("cluster session {} closed: {}", session.id(), closeReason);
    }

    @Override
    public void onSessionMessage(
            ClientSession session, long timestamp, DirectBuffer buffer, int offset, int length, Header header) {
        try {
            dispatch(session, timestamp, buffer, offset, header);
        } catch (StateVersions.UnsupportedStateVersionException e) {
            // applying further entries with older rules would diverge from the other members: stop here
            LOG.error("stopping this member's service: {}", e.getMessage());
            stats.fatal(e.getMessage());
            throw new org.agrona.concurrent.AgentTerminationException(e);
        }
    }

    private void dispatch(ClientSession session, long timestamp, DirectBuffer buffer, int offset, Header header) {
        headerDecoder.wrap(buffer, offset);
        if (headerDecoder.schemaId() != MessageHeaderDecoder.SCHEMA_ID) {
            return; // not ours; ignoring is deterministic
        }
        switch (headerDecoder.templateId()) {
            case io.radiusward.protocol.AccountingCommandDecoder.TEMPLATE_ID ->
                onCommand(session, timestamp, buffer, offset, header);
            case ExportCheckpointDecoder.TEMPLATE_ID -> onCheckpoint(session, timestamp, buffer, offset, header);
            case io.radiusward.protocol.SinkQueryDecoder.TEMPLATE_ID -> {
                sinkQueryDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                replySinks(session, sinkQueryDecoder.correlationId());
            }
            case io.radiusward.protocol.SinkResyncDecoder.TEMPLATE_ID -> {
                applier.apply(buffer, offset, header.position(), timestamp);
                stats.purgeInputs(machine.export());
                replySinks(session, applier.resync().correlationId());
            }
            case io.radiusward.protocol.MemberLogPositionDecoder.TEMPLATE_ID -> {
                applier.apply(buffer, offset, header.position(), timestamp);
                stats.purgeInputs(machine.export());
                onVersions(applier.activatedVersion(), "every member supports it", header.position());
            }
            case io.radiusward.protocol.ActivateVersionDecoder.TEMPLATE_ID -> {
                applier.apply(buffer, offset, header.position(), timestamp);
                onVersions(applier.activatedVersion(), "requested", header.position());
                activationEncoder
                        .wrapAndApplyHeader(egressBuffer, 0, headerEncoder)
                        .correlationId(applier.activation().correlationId())
                        .result(
                                switch (applier.activationResult()) {
                                    case StateVersions.ACTIVATED -> io.radiusward.protocol.ActivationResult.ACTIVATED;
                                    case StateVersions.NOT_NEWER -> io.radiusward.protocol.ActivationResult.NOT_NEWER;
                                    default -> io.radiusward.protocol.ActivationResult.MEMBERS_NOT_READY;
                                })
                        .activeVersion(machine.versions().active())
                        .lowestSupportedVersion(machine.versions().lowestSupported());
                if (session != null) {
                    reply(session, MessageHeaderEncoder.ENCODED_LENGTH + activationEncoder.encodedLength());
                }
            }
            case io.radiusward.protocol.AuthReservationDecoder.TEMPLATE_ID -> {
                applier.apply(buffer, offset, header.position(), timestamp);
                if (applier.claimSweepTimer()) {
                    scheduleSweep(timestamp); // expired reservations are removed by the sweep
                }
                reservationEncoder
                        .wrapAndApplyHeader(egressBuffer, 0, headerEncoder)
                        .correlationId(applier.reservation().correlationId())
                        .result(
                                switch (applier.reservationResult()) {
                                    case AccountingStateMachine.RESERVATION_GRANTED ->
                                        io.radiusward.protocol.ReservationResult.GRANTED;
                                    case AccountingStateMachine.RESERVATION_DENIED ->
                                        io.radiusward.protocol.ReservationResult.DENIED;
                                    case AccountingStateMachine.RESERVATION_UNSUPPORTED ->
                                        io.radiusward.protocol.ReservationResult.UNSUPPORTED;
                                    default -> io.radiusward.protocol.ReservationResult.CAPACITY;
                                });
                if (session != null) {
                    reply(session, MessageHeaderEncoder.ENCODED_LENGTH + reservationEncoder.encodedLength());
                }
            }
            case io.radiusward.protocol.SqnNextDecoder.TEMPLATE_ID -> {
                applier.apply(buffer, offset, header.position(), timestamp);
                long sqn = applier.sqnResult();
                sqnEncoder
                        .wrapAndApplyHeader(egressBuffer, 0, headerEncoder)
                        .correlationId(applier.sqnRequest().correlationId())
                        .outcome(
                                sqn >= 0
                                        ? io.radiusward.protocol.SqnOutcome.OK
                                        : sqn == AccountingStateMachine.SQN_UNSUPPORTED
                                                ? io.radiusward.protocol.SqnOutcome.UNSUPPORTED
                                                : io.radiusward.protocol.SqnOutcome.CAPACITY)
                        .sqn(Math.max(sqn, 0));
                if (session != null) {
                    reply(session, MessageHeaderEncoder.ENCODED_LENGTH + sqnEncoder.encodedLength());
                }
            }
            case StateQueryDecoder.TEMPLATE_ID -> onStateQuery(session, buffer, offset);
            case SessionQueryDecoder.TEMPLATE_ID -> onSessionQuery(session, buffer, offset);
            case io.radiusward.protocol.UserSessionsQueryDecoder.TEMPLATE_ID ->
                onUserSessionsQuery(session, buffer, offset);
            case io.radiusward.protocol.SessionPageQueryDecoder.TEMPLATE_ID ->
                onSessionPageQuery(session, buffer, offset);
            default -> {}
        }
    }

    private void onCommand(ClientSession session, long timestamp, DirectBuffer buffer, int offset, Header header) {
        int outcome = applier.apply(buffer, offset, header.position(), timestamp);
        if (outcome == Outcomes.REJECTED_EXPORT_LAG) {
            stats.recordExportLagRejection();
        }
        checkIdentity(applier.command());
        if (applier.claimSweepTimer()) {
            scheduleSweep(timestamp);
        }
        long correlationId = applier.command().correlationId();
        if (session != null) {
            if (Outcomes.acknowledged(outcome)) {
                committedEncoder
                        .wrapAndApplyHeader(egressBuffer, 0, headerEncoder)
                        .correlationId(correlationId)
                        .outcome(
                                switch (outcome) {
                                    case Outcomes.APPLIED, Outcomes.MERGED -> Outcome.APPLIED;
                                    case Outcomes.DUPLICATE -> Outcome.DUPLICATE;
                                    default -> Outcome.STALE;
                                })
                        .eventId(header.position());
                reply(session, MessageHeaderEncoder.ENCODED_LENGTH + committedEncoder.encodedLength());
            } else {
                rejectedEncoder
                        .wrapAndApplyHeader(egressBuffer, 0, headerEncoder)
                        .correlationId(correlationId)
                        .reason(
                                outcome == Outcomes.REJECTED_EXPORT_LAG
                                        ? RejectReason.EXPORT_LAG
                                        : RejectReason.CAPACITY);
                reply(session, MessageHeaderEncoder.ENCODED_LENGTH + rejectedEncoder.encodedLength());
            }
        }
        publishStats(header.position());
    }

    /** Counts commands of a NAS entry whose gateway has another identity setting than the first one seen. */
    private void checkIdentity(io.radiusward.protocol.AccountingCommandDecoder command) {
        if (command.actingVersion() < 3) {
            return; // written before device identities existed
        }
        int nas = command.nasClientId();
        int fingerprint = command.identityFingerprint();
        int known = identityByNas.get(nas);
        if (known == Integer.MIN_VALUE) {
            identityByNas.put(nas, fingerprint);
        } else if (known != fingerprint) {
            stats.recordIdentityMismatch();
            if (stats.identityMismatches() == 1) {
                LOG.warn(
                        "NAS entry {}: gateways disagree on nas.<name>.identity (gateway {}); sessions of its devices"
                                + " are split between them — configure every gateway alike",
                        nas,
                        command.gatewayId());
            }
        }
    }

    private void onCheckpoint(ClientSession session, long timestamp, DirectBuffer buffer, int offset, Header header) {
        applier.apply(buffer, offset, header.position(), timestamp);
        ExportState export = machine.export();
        int slot = applier.sinkSlot();
        checkpointAckEncoder
                .wrapAndApplyHeader(egressBuffer, 0, headerEncoder)
                .correlationId(applier.checkpoint().correlationId())
                .result(
                        switch (applier.leaseResult()) {
                            case ExportState.GRANTED -> LeaseResult.GRANTED;
                            case ExportState.NOT_OWNER -> LeaseResult.NOT_OWNER;
                            default -> LeaseResult.FULL;
                        })
                .owner(slot < 0 ? -1 : export.owner(slot))
                .epoch(slot < 0 ? 0 : export.epoch(slot))
                .checkpoint(slot < 0 ? 0 : export.checkpoint(slot))
                .detached((short) (slot >= 0 && export.detached(slot) ? 1 : 0))
                .resync((short) (slot >= 0 && export.resyncFrom(slot) >= 0 ? 1 : 0));
        if (session != null) {
            reply(session, MessageHeaderEncoder.ENCODED_LENGTH + checkpointAckEncoder.encodedLength());
        }
        // no publishStats: the published position is that of the last accounting entry, so lag on /state
        // counts accounting not yet exported, not the checkpoints themselves
    }

    private void replySinks(ClientSession session, long correlationId) {
        ExportState export = machine.export();
        io.radiusward.protocol.SinkReportEncoder.SinksEncoder sinks = sinkReportEncoder
                .wrapAndApplyHeader(sinkBuffer, 0, headerEncoder)
                .correlationId(correlationId)
                .logPosition(export.lastCommandPosition())
                .sinksCount(export.count());
        byte[] name = new byte[ExportState.NAME_LENGTH];
        for (int i = 0; i < export.count(); i++) {
            java.util.Arrays.fill(name, (byte) 0);
            byte[] ascii = export.name(i).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            System.arraycopy(ascii, 0, name, 0, Math.min(ascii.length, name.length));
            sinks.next()
                    .putName(name, 0)
                    .checkpoint(export.checkpoint(i))
                    .owner(export.owner(i))
                    .epoch(export.epoch(i))
                    .leaseExpiry(export.leaseExpiry(i))
                    .required((short) (export.required(i) ? 1 : 0))
                    .detached((short) (export.detached(i) ? 1 : 0))
                    .resync((short) (export.resyncFrom(i) >= 0 ? 1 : 0));
        }
        if (session != null) {
            int length = MessageHeaderEncoder.ENCODED_LENGTH + sinkReportEncoder.encodedLength();
            for (int attempt = 0; attempt < 3; attempt++) {
                long result = session.offer(sinkBuffer, 0, length);
                if (result > 0 || result == Publication.NOT_CONNECTED || result == Publication.CLOSED) {
                    return;
                }
                idleStrategy.idle();
            }
        }
    }

    /** Logs an activation and warns once while every member supports a newer version that a hold keeps off. */
    private void onVersions(int activated, String why, long position) {
        StateVersions v = machine.versions();
        if (activated != 0) {
            LOG.info("state version {} active from log position {} ({})", activated, position, why);
            holdWarned = false;
        } else if (v.held() && v.lowestSupported() > v.active() && !holdWarned) {
            holdWarned = true;
            LOG.warn(
                    "every member supports state version {}, the cluster applies {}: activation is held"
                            + " (cluster.version.hold); `admin activate-version --version {}` activates it",
                    v.lowestSupported(),
                    v.active(),
                    v.lowestSupported());
        }
        stats.versions(v.active(), v.lowestSupported(), v.held());
    }

    private void onStateQuery(ClientSession session, DirectBuffer buffer, int offset) {
        stateQueryDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
        stateReportEncoder
                .wrapAndApplyHeader(egressBuffer, 0, headerEncoder)
                .correlationId(stateQueryDecoder.correlationId())
                .applied(machine.applied())
                .duplicates(machine.duplicates())
                .stale(machine.stale())
                .rejected(machine.rejected())
                .activeSessions(machine.store().activeCount())
                .stoppedSessions(machine.store().stoppedCount())
                .stateDigest(machine.digest())
                .stateVersion(AccountingStateMachine.STATE_VERSION)
                .activeVersion(machine.versions().active())
                .lowestSupportedVersion(machine.versions().lowestSupported());
        if (session != null) {
            reply(session, MessageHeaderEncoder.ENCODED_LENGTH + stateReportEncoder.encodedLength());
        }
    }

    private void onSessionQuery(ClientSession session, DirectBuffer buffer, int offset) {
        sessionQueryDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
        SessionStore store = machine.store();
        int slot = store.find(sessionQueryDecoder.sessionKeyHi(), sessionQueryDecoder.sessionKeyLo());
        sessionReportEncoder
                .wrapAndApplyHeader(egressBuffer, 0, headerEncoder)
                .correlationId(sessionQueryDecoder.correlationId());
        if (slot < 0) {
            sessionReportEncoder
                    .status(SessionStatus.UNKNOWN)
                    .nasId(0)
                    .statusType(0)
                    .sessionTime(0)
                    .eventTimestamp(0)
                    .inputOctets(0)
                    .outputOctets(0);
        } else {
            sessionReportEncoder
                    .status(store.state(slot) == SessionStore.ACTIVE ? SessionStatus.ACTIVE : SessionStatus.STOPPED)
                    .nasId(store.nasId(slot))
                    .statusType(store.statusType(slot))
                    .sessionTime(store.sessionTime(slot))
                    .eventTimestamp(store.eventTimestamp(slot))
                    .inputOctets(store.inputOctets(slot))
                    .outputOctets(store.outputOctets(slot));
        }
        int identity = slot < 0 ? 0 : store.identity(slot, identityScratch, 0);
        sessionReportEncoder.putIdentity(identityScratch, 0, identity);
        if (session != null) {
            reply(session, MessageHeaderEncoder.ENCODED_LENGTH + sessionReportEncoder.encodedLength());
        }
    }

    /**
     * The active sessions of a user, at most {@link #MAX_LISTED} (ADR 0036). A scan of the store: an operator's or a
     * Simultaneous-Use question, not one per accounting packet.
     */
    private void onUserSessionsQuery(ClientSession session, DirectBuffer buffer, int offset) {
        userSessionsQueryDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
        long user = userSessionsQueryDecoder.userKey();
        SessionStore store = machine.store();
        int count = 0;
        for (int slot = 0, n = store.highWater(); slot < n && count < MAX_LISTED; slot++) {
            if (user != 0 && store.state(slot) == SessionStore.ACTIVE && store.userKey(slot) == user) {
                count++;
            }
        }
        io.radiusward.protocol.UserSessionsReportEncoder.SessionsEncoder sessions = userSessionsReportEncoder
                .wrapAndApplyHeader(listBuffer, 0, headerEncoder)
                .correlationId(userSessionsQueryDecoder.correlationId())
                .sessionsCount(count);
        for (int slot = 0, n = store.highWater(), written = 0; slot < n && written < count; slot++) {
            if (store.state(slot) == SessionStore.ACTIVE && store.userKey(slot) == user) {
                int length = store.identity(slot, identityScratch, 0);
                sessions.next()
                        .keyHi(store.keyHi(slot))
                        .keyLo(store.keyLo(slot))
                        .nasId(store.nasId(slot))
                        .firstSeen(store.firstSeen(slot))
                        .lastSeen(store.lastSeen(slot))
                        .putIdentity(identityScratch, 0, length);
                written++;
            }
        }
        if (session != null) {
            replyList(session, MessageHeaderEncoder.ENCODED_LENGTH + userSessionsReportEncoder.encodedLength());
        }
    }

    /** A page of active sessions with a user, from a slot on (the gateways' store sweep, ADR 0036). */
    private void onSessionPageQuery(ClientSession session, DirectBuffer buffer, int offset) {
        sessionPageQueryDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
        SessionStore store = machine.store();
        int limit = Math.max(1, Math.min(MAX_LISTED, sessionPageQueryDecoder.maxSessions()));
        int from = Math.max(0, sessionPageQueryDecoder.fromSlot());
        int n = store.highWater();
        int count = 0;
        int slot = from;
        for (; slot < n && count < limit; slot++) {
            if (store.state(slot) == SessionStore.ACTIVE && store.userKey(slot) != 0) {
                count++;
            }
        }
        io.radiusward.protocol.SessionPageReportEncoder.SessionsEncoder sessions = sessionPageReportEncoder
                .wrapAndApplyHeader(listBuffer, 0, headerEncoder)
                .correlationId(sessionPageQueryDecoder.correlationId())
                .nextSlot(slot >= n ? -1 : slot)
                .sessionsCount(count);
        for (int s = from, written = 0; written < count; s++) {
            if (store.state(s) == SessionStore.ACTIVE && store.userKey(s) != 0) {
                int length = store.identity(s, identityScratch, 0);
                sessions.next()
                        .keyHi(store.keyHi(s))
                        .keyLo(store.keyLo(s))
                        .nasId(store.nasId(s))
                        .userKey(store.userKey(s))
                        .putIdentity(identityScratch, 0, length);
                written++;
            }
        }
        if (session != null) {
            replyList(session, MessageHeaderEncoder.ENCODED_LENGTH + sessionPageReportEncoder.encodedLength());
        }
    }

    private void replyList(ClientSession session, int length) {
        for (int attempt = 0; attempt < MAX_EGRESS_ATTEMPTS; attempt++) {
            long result = session.offer(listBuffer, 0, length);
            if (result > 0 || result == Publication.NOT_CONNECTED || result == Publication.CLOSED) {
                return;
            }
            idleStrategy.idle();
        }
        stats.recordEgressDropped();
    }

    /**
     * Sends a reply, retrying briefly on back pressure. Giving up only costs the NAS a retransmit, which is
     * then answered as a duplicate; it never affects replicated state.
     */
    private void reply(ClientSession session, int length) {
        for (int attempt = 0; attempt < MAX_EGRESS_ATTEMPTS; attempt++) {
            long result = session.offer(egressBuffer, 0, length);
            if (result > 0 || result == Publication.NOT_CONNECTED || result == Publication.CLOSED) {
                return;
            }
            idleStrategy.idle();
        }
        stats.recordEgressDropped();
    }

    private void scheduleSweep(long now) {
        while (!cluster.scheduleTimer(LogApplier.SWEEP_TIMER_ID, now + sweepIntervalMs)) {
            idleStrategy.idle();
        }
    }

    @Override
    public void onTimerEvent(long correlationId, long timestamp) {
        if (applier.onTimer(correlationId, timestamp)) {
            scheduleSweep(timestamp);
            publishStats(stats.lastPosition());
        }
    }

    @Override
    public void onTakeSnapshot(ExclusivePublication snapshotPublication) {
        snapshotCodec.write(machine, (buffer, offset, length) -> {
            while (snapshotPublication.offer(buffer, offset, length) < 0) {
                idleStrategy.idle();
            }
        });
        stats.snapshotTaken();
        LOG.info("snapshot taken: {} sessions, digest {}", machine.store().size(), Long.toHexString(machine.digest()));
    }

    @Override
    public void onRoleChange(Cluster.Role newRole) {
        stats.role(newRole.name());
        LOG.info("role changed to {}", newRole);
    }

    @Override
    public void onNewLeadershipTermEvent(
            long leadershipTermId,
            long logPosition,
            long timestamp,
            long termBaseLogPosition,
            int leaderMemberId,
            int logSessionId,
            java.util.concurrent.TimeUnit timeUnit,
            int appVersion) {
        stats.leadership(leadershipTermId, leaderMemberId);
    }

    @Override
    public void onTerminate(Cluster cluster) {
        LOG.info("terminating");
    }

    private void publishStats(long position) {
        stats.update(
                machine.applied(),
                machine.duplicates(),
                machine.stale(),
                machine.rejected(),
                machine.store().activeCount(),
                machine.store().stoppedCount(),
                machine.digest(),
                position);
        stats.purgeInputs(machine.export());
        stats.versions(
                machine.versions().active(),
                machine.versions().lowestSupported(),
                machine.versions().held());
    }

    /** For tests in this package. */
    AccountingStateMachine machine() {
        return machine;
    }
}
