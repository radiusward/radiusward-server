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
    private final SnapshotCodec snapshotCodec = new SnapshotCodec();

    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final SessionQueryDecoder sessionQueryDecoder = new SessionQueryDecoder();
    private final StateQueryDecoder stateQueryDecoder = new StateQueryDecoder();
    private final AccountingCommittedEncoder committedEncoder = new AccountingCommittedEncoder();
    private final AccountingRejectedEncoder rejectedEncoder = new AccountingRejectedEncoder();
    private final SessionReportEncoder sessionReportEncoder = new SessionReportEncoder();
    private final StateReportEncoder stateReportEncoder = new StateReportEncoder();
    private final ExportCheckpointAckEncoder checkpointAckEncoder = new ExportCheckpointAckEncoder();
    private final UnsafeBuffer egressBuffer = new UnsafeBuffer(new byte[256]);

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
        headerDecoder.wrap(buffer, offset);
        if (headerDecoder.schemaId() != MessageHeaderDecoder.SCHEMA_ID) {
            return; // not ours; ignoring is deterministic
        }
        switch (headerDecoder.templateId()) {
            case io.radiusward.protocol.AccountingCommandDecoder.TEMPLATE_ID ->
                onCommand(session, timestamp, buffer, offset, header);
            case ExportCheckpointDecoder.TEMPLATE_ID -> onCheckpoint(session, timestamp, buffer, offset, header);
            case io.radiusward.protocol.MemberLogPositionDecoder.TEMPLATE_ID -> {
                applier.apply(buffer, offset, header.position(), timestamp);
                stats.purgeInputs(machine.export());
            }
            case StateQueryDecoder.TEMPLATE_ID -> onStateQuery(session, buffer, offset);
            case SessionQueryDecoder.TEMPLATE_ID -> onSessionQuery(session, buffer, offset);
            default -> {}
        }
    }

    private void onCommand(ClientSession session, long timestamp, DirectBuffer buffer, int offset, Header header) {
        int outcome = applier.apply(buffer, offset, header.position(), timestamp);
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
                                    case Outcomes.APPLIED -> Outcome.APPLIED;
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
                .detached((short) (slot >= 0 && export.detached(slot) ? 1 : 0));
        if (session != null) {
            reply(session, MessageHeaderEncoder.ENCODED_LENGTH + checkpointAckEncoder.encodedLength());
        }
        // no publishStats: the published position is that of the last accounting entry, so lag on /state
        // counts accounting not yet exported, not the checkpoints themselves
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
                .stateVersion(AccountingStateMachine.STATE_VERSION);
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
        if (session != null) {
            reply(session, MessageHeaderEncoder.ENCODED_LENGTH + sessionReportEncoder.encodedLength());
        }
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
    }

    /** For tests in this package. */
    AccountingStateMachine machine() {
        return machine;
    }
}
