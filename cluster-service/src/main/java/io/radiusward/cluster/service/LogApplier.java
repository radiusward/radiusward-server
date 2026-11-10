/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import io.radiusward.protocol.AccountingCommandDecoder;
import io.radiusward.protocol.ExportCheckpointDecoder;
import io.radiusward.protocol.MemberLogPositionDecoder;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.OnMaxLag;
import io.radiusward.protocol.SinkResyncDecoder;
import org.agrona.DirectBuffer;

/**
 * Applies the replicated log to an {@link AccountingStateMachine}: the one place that turns log entries into
 * state changes. {@link AccountingService} runs it inside the cluster; the exporter runs a second instance
 * over the same log to learn each event's outcome, so both always decide identically.
 *
 * <p>Timer scheduling is the caller's job (only the service can schedule); whether a sweep timer is due is
 * part of the replicated state ({@link AccountingStateMachine#timerScheduled()}).
 */
public final class LogApplier {

    /** Correlation id of the housekeeping timer (rescheduled with the same id, so never duplicated). */
    public static final long SWEEP_TIMER_ID = 1;

    /** {@link #apply} result for a message that changes no state (queries, foreign schemas). */
    public static final int NOT_A_COMMAND = -1;

    /** {@link #apply} result for an {@code ExportCheckpoint}; see {@link #leaseResult()}. */
    public static final int CHECKPOINT = -2;

    /** {@link #apply} result for a {@code SinkResync}. */
    public static final int RESYNC = -4;

    /** {@link #apply} result for a {@code MemberLogPosition}. */
    public static final int MEMBER_POSITION = -3;

    /** An {@code ActivateVersion} request; {@link #activationResult()} holds the result. */
    public static final int ACTIVATION = -5;

    /** An {@code AuthReservation}; {@link #reservationResult()} holds the result (state version 6). */
    public static final int AUTH_RESERVATION = -6;

    private final AccountingStateMachine machine;
    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final AccountingCommandDecoder commandDecoder = new AccountingCommandDecoder();
    private final AccountingCommandDecoder identityDecoder = new AccountingCommandDecoder();
    private final io.radiusward.protocol.MessageHeaderDecoder identityHeader =
            new io.radiusward.protocol.MessageHeaderDecoder();
    private final org.agrona.concurrent.UnsafeBuffer rawView = new org.agrona.concurrent.UnsafeBuffer(0, 0);
    private final org.agrona.concurrent.UnsafeBuffer identityScratch =
            new org.agrona.concurrent.UnsafeBuffer(new byte[SessionStore.IDENTITY_SIZE]);
    private final ExportCheckpointDecoder checkpointDecoder = new ExportCheckpointDecoder();
    private final MemberLogPositionDecoder memberPositionDecoder = new MemberLogPositionDecoder();
    private final SinkResyncDecoder resyncDecoder = new SinkResyncDecoder();
    private final io.radiusward.protocol.ActivateVersionDecoder activateDecoder =
            new io.radiusward.protocol.ActivateVersionDecoder();
    private final io.radiusward.protocol.AuthReservationDecoder reservationDecoder =
            new io.radiusward.protocol.AuthReservationDecoder();
    private int reservationResult;
    private int activationResult;
    private int activatedVersion;
    private final byte[] sinkName = new byte[ExportState.NAME_LENGTH];
    private int leaseResult;
    private int sinkSlot = -1;

    public LogApplier(AccountingStateMachine machine) {
        this.machine = machine;
    }

    public AccountingStateMachine machine() {
        return machine;
    }

    /**
     * Applies one session message of the log entry at {@code position} with cluster time {@code timestamp}.
     *
     * @return an {@link Outcomes} value for an {@code AccountingCommand} (then {@link #command()} holds it),
     *     {@link #CHECKPOINT} for an {@code ExportCheckpoint}, otherwise {@link #NOT_A_COMMAND}
     */
    public int apply(DirectBuffer buffer, int offset, long position, long timestamp) {
        headerDecoder.wrap(buffer, offset);
        if (headerDecoder.schemaId() != MessageHeaderDecoder.SCHEMA_ID) {
            return NOT_A_COMMAND;
        }
        return switch (headerDecoder.templateId()) {
            case AccountingCommandDecoder.TEMPLATE_ID -> applyCommand(buffer, offset, position, timestamp);
            case ExportCheckpointDecoder.TEMPLATE_ID -> applyCheckpoint(buffer, offset, timestamp);
            case SinkResyncDecoder.TEMPLATE_ID -> {
                resyncDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                int n = resyncDecoder.getSinkName(sinkName, 0);
                int end = 0;
                while (end < n && sinkName[end] != 0) {
                    end++;
                }
                machine.export()
                        .resync(
                                new String(sinkName, 0, end, java.nio.charset.StandardCharsets.US_ASCII),
                                resyncDecoder.position());
                yield RESYNC;
            }
            case MemberLogPositionDecoder.TEMPLATE_ID -> {
                memberPositionDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                machine.export().memberPosition(memberPositionDecoder.memberId(), memberPositionDecoder.logPosition());
                activatedVersion = memberPositionDecoder.actingVersion() >= 5
                        ? machine.reportMemberVersion(
                                memberPositionDecoder.memberId(),
                                memberPositionDecoder.supportedVersion(),
                                memberPositionDecoder.clusterSize(),
                                memberPositionDecoder.hold() != 0)
                        : 0;
                yield MEMBER_POSITION;
            }
            case io.radiusward.protocol.ActivateVersionDecoder.TEMPLATE_ID -> {
                activateDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                activationResult = machine.activateVersion(activateDecoder.version());
                activatedVersion = activationResult == StateVersions.ACTIVATED ? activateDecoder.version() : 0;
                yield ACTIVATION;
            }
            case io.radiusward.protocol.AuthReservationDecoder.TEMPLATE_ID -> {
                reservationDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
                reservationResult = machine.reserve(
                        reservationDecoder.userKey(),
                        reservationDecoder.deviceKey(),
                        reservationDecoder.maxDevices(),
                        reservationDecoder.ttlSeconds() * 1000L,
                        timestamp);
                yield AUTH_RESERVATION;
            }
            default -> NOT_A_COMMAND;
        };
    }

    /** The {@code AuthReservation} decoded by the last {@link #apply} that returned {@link #AUTH_RESERVATION}. */
    public io.radiusward.protocol.AuthReservationDecoder reservation() {
        return reservationDecoder;
    }

    /** {@link AccountingStateMachine#reserve} result of the last {@link #AUTH_RESERVATION}. */
    public int reservationResult() {
        return reservationResult;
    }

    private int applyCommand(DirectBuffer buffer, int offset, long position, long timestamp) {
        commandDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
        ExportState export = machine.export();
        int outcome;
        if (export.blocks(position, timestamp)) {
            machine.countRejected();
            outcome = Outcomes.REJECTED_EXPORT_LAG;
        } else {
            int flags = 0;
            if (commandDecoder.flags().sessionTimePresent()) {
                flags |= AccountingStateMachine.FLAG_SESSION_TIME;
            }
            if (commandDecoder.flags().eventTimestampPresent()) {
                flags |= AccountingStateMachine.FLAG_EVENT_TIMESTAMP;
            }
            if (commandDecoder.flags().deviceUnknown()) {
                flags |= AccountingStateMachine.FLAG_DEVICE_UNKNOWN;
            }
            outcome = machine.apply(
                    commandDecoder.sessionKeyHi(),
                    commandDecoder.sessionKeyLo(),
                    commandDecoder.exactKeyHi(),
                    commandDecoder.exactKeyLo(),
                    commandDecoder.nasId(),
                    (int) commandDecoder.statusType(),
                    flags,
                    commandDecoder.sessionTime(),
                    commandDecoder.eventTimestamp(),
                    commandDecoder.inputOctets(),
                    commandDecoder.outputOctets(),
                    commandDecoder.actingVersion() >= 4 ? commandDecoder.idleTimeoutMinutes() : 0,
                    commandDecoder.actingVersion() >= 6 ? commandDecoder.userKey() : 0,
                    commandDecoder.actingVersion() >= 6 ? commandDecoder.deviceKey() : 0,
                    identityScratch,
                    0,
                    identity(buffer, offset),
                    timestamp);
        }
        export.commandProcessed(position);
        return outcome;
    }

    /**
     * The session's identifying attributes from the command's attribute section (ADR 0036), read with a decoder of its
     * own: the command decoder's variable-length fields stay unread for the exporter.
     */
    private int identity(DirectBuffer buffer, int offset) {
        identityDecoder.wrapAndApplyHeader(buffer, offset, identityHeader);
        identityDecoder.skipSessionId();
        identityDecoder.wrapRawAttributes(rawView);
        return SessionIdentity.extract(rawView, 0, rawView.capacity(), identityScratch, 0);
    }

    private int applyCheckpoint(DirectBuffer buffer, int offset, long timestamp) {
        checkpointDecoder.wrapAndApplyHeader(buffer, offset, headerDecoder);
        int length = checkpointDecoder.getSinkName(sinkName, 0);
        int end = 0;
        while (end < length && sinkName[end] != 0) {
            end++;
        }
        String name = new String(sinkName, 0, end, java.nio.charset.StandardCharsets.US_ASCII);
        ExportState export = machine.export();
        leaseResult = export.checkpoint(
                name,
                checkpointDecoder.memberId(),
                checkpointDecoder.epoch(),
                checkpointDecoder.position(),
                checkpointDecoder.lastEventTime(),
                checkpointDecoder.leaseTimeoutMs(),
                checkpointDecoder.required() != 0,
                checkpointDecoder.maxLagBytes(),
                checkpointDecoder.maxLagMs(),
                checkpointDecoder.onMaxLag() == OnMaxLag.DETACH
                        ? ExportState.ON_MAX_LAG_DETACH
                        : ExportState.ON_MAX_LAG_BLOCK,
                timestamp);
        sinkSlot = export.find(name);
        return CHECKPOINT;
    }

    /** The command decoded by the last {@link #apply} that returned an outcome. */
    public AccountingCommandDecoder command() {
        return commandDecoder;
    }

    /** The {@code ActivateVersion} decoded by the last {@link #apply} that returned {@link #ACTIVATION}. */
    public io.radiusward.protocol.ActivateVersionDecoder activation() {
        return activateDecoder;
    }

    /** {@link StateVersions} result of the last {@link #ACTIVATION}. */
    public int activationResult() {
        return activationResult;
    }

    /** Version activated by the last {@link #MEMBER_POSITION} or {@link #ACTIVATION}, 0 if none. */
    public int activatedVersion() {
        return activatedVersion;
    }

    /** The resync decoded by the last {@link #apply} that returned {@link #RESYNC}. */
    public SinkResyncDecoder resync() {
        return resyncDecoder;
    }

    /** The checkpoint decoded by the last {@link #apply} that returned {@link #CHECKPOINT}. */
    public ExportCheckpointDecoder checkpoint() {
        return checkpointDecoder;
    }

    /** {@link ExportState#GRANTED}, {@link ExportState#NOT_OWNER} or {@link ExportState#FULL}. */
    public int leaseResult() {
        return leaseResult;
    }

    /** Slot of the sink of the last checkpoint in {@link ExportState}, or -1 if it did not fit. */
    public int sinkSlot() {
        return sinkSlot;
    }

    /**
     * Whether a sweep timer has to be scheduled after a command; marks it as scheduled in the replicated state.
     * The service schedules it; a replica only records the flag.
     */
    public boolean claimSweepTimer() {
        if (machine.timerScheduled()) {
            return false;
        }
        machine.timerScheduled(true);
        return true;
    }

    /** Applies a timer event; returns whether it was the sweep timer (which the service reschedules). */
    public boolean onTimer(long correlationId, long timestamp) {
        if (correlationId != SWEEP_TIMER_ID) {
            return false;
        }
        machine.sweep(timestamp);
        return true;
    }
}
