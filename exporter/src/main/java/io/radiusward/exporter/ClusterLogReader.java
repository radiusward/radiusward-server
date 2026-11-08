/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.aeron.Aeron;
import io.aeron.AeronCounters;
import io.aeron.ChannelUri;
import io.aeron.ControlledFragmentAssembler;
import io.aeron.Image;
import io.aeron.Subscription;
import io.aeron.archive.client.AeronArchive;
import io.aeron.cluster.RecordingLog;
import io.aeron.cluster.client.AeronCluster;
import io.aeron.cluster.codecs.MessageHeaderDecoder;
import io.aeron.cluster.codecs.SessionMessageHeaderDecoder;
import io.aeron.cluster.codecs.TimerEventDecoder;
import io.aeron.logbuffer.ControlledFragmentHandler;
import io.aeron.logbuffer.Header;
import java.io.File;
import org.agrona.CloseHelper;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.status.CountersReader;

/**
 * Reads this member's copy of the replicated log from its local archive, never past the member's commit
 * position: entries above it are not committed yet and an election may truncate them.
 *
 * <p>The cluster log is framed with Aeron Cluster's own codecs (schema of {@link MessageHeaderDecoder}). Only
 * what the clustered service sees is passed on: client session messages (with the cluster timestamp) and
 * timer events. Everything Aeron-specific about the format lives in this class.
 */
public final class ClusterLogReader implements AutoCloseable {

    /** What the clustered service would see, in log order. */
    public interface Listener {
        /** A client message; {@code position} is the log position after it (the service's event id). */
        void onSessionMessage(long position, long timestamp, DirectBuffer buffer, int offset, int length);

        void onTimer(long position, long correlationId, long timestamp);
    }

    private static final String REPLAY_CHANNEL = "aeron:ipc?term-length=1m";

    private final Aeron aeron;
    private final AeronArchive archive;
    private final File clusterDir;
    private final int replayStreamId;
    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final SessionMessageHeaderDecoder sessionHeaderDecoder = new SessionMessageHeaderDecoder();
    private final TimerEventDecoder timerDecoder = new TimerEventDecoder();
    private final ControlledFragmentAssembler assembler = new ControlledFragmentAssembler(this::onFragment);

    private int commitPositionCounterId = -1;
    private long replaySessionId = Aeron.NULL_VALUE;
    private long position = Aeron.NULL_VALUE;
    private long reopens;
    private Subscription subscription;
    private Image image;
    private Listener listener;

    public ClusterLogReader(Aeron aeron, AeronArchive archive, File clusterDir, int replayStreamId) {
        this.aeron = aeron;
        this.archive = archive;
        this.clusterDir = clusterDir;
        this.replayStreamId = replayStreamId;
    }

    /** The member's commit position, or {@link Aeron#NULL_VALUE} while the consensus module has none. */
    public long commitPosition() {
        CountersReader counters = aeron.countersReader();
        if (commitPositionCounterId < 0
                || counters.getCounterState(commitPositionCounterId) != CountersReader.RECORD_ALLOCATED) {
            commitPositionCounterId = findCounter(counters, AeronCounters.CLUSTER_COMMIT_POSITION_TYPE_ID);
            if (commitPositionCounterId < 0) {
                return Aeron.NULL_VALUE;
            }
        }
        return counters.getCounterValue(commitPositionCounterId);
    }

    private static int findCounter(CountersReader counters, int typeId) {
        int[] found = {-1};
        counters.forEach((counterId, type, keyBuffer, label) -> {
            if (type == typeId && found[0] < 0) {
                found[0] = counterId;
            }
        });
        return found[0];
    }

    /** Recording id of the log (the last leadership term's recording). */
    public long logRecordingId() {
        try (RecordingLog recordingLog = new RecordingLog(clusterDir, false)) {
            RecordingLog.Entry term = recordingLog.findLastTerm();
            if (term == null) {
                throw new IllegalStateException("no leadership term in the recording log of " + clusterDir);
            }
            return term.recordingId;
        }
    }

    /** Starts reading the log at {@code position} (a message boundary: 0, a snapshot or a checkpoint). */
    public void open(long position) {
        close();
        this.position = position;
        long recordingId = logRecordingId();
        replaySessionId = archive.startReplay(
                recordingId, position, AeronArchive.REPLAY_ALL_AND_FOLLOW, REPLAY_CHANNEL, replayStreamId);
        String channel = ChannelUri.addSessionId(REPLAY_CHANNEL, (int) replaySessionId);
        subscription = aeron.addSubscription(channel, replayStreamId);
        image = null;
    }

    /**
     * Delivers committed entries to {@code listener}; returns the number of fragments read (0 when caught up
     * with the commit position or the replay is not connected yet).
     */
    public int poll(Listener listener, int fragmentLimit) {
        if (image == null) {
            image = subscription.imageBySessionId((int) replaySessionId);
            if (image == null) {
                return 0;
            }
        }
        long limit = commitPosition();
        if (limit == Aeron.NULL_VALUE || limit <= position) {
            return 0;
        }
        if (image.isClosed() || image.isEndOfStream()) {
            // An election stops and later extends the log recording, which ends a replay that follows it.
            // Committed data beyond our position exists, so replay again from where we stopped.
            reopens++;
            open(position);
            return 0;
        }
        this.listener = listener;
        int fragments = image.boundedControlledPoll(assembler, limit, fragmentLimit);
        position = image.position();
        return fragments;
    }

    /** Log position up to which entries have been delivered. */
    public long position() {
        return position;
    }

    /** How often a replay had to be restarted (each election that touches this member's recording). */
    public long reopens() {
        return reopens;
    }

    private ControlledFragmentHandler.Action onFragment(DirectBuffer buffer, int offset, int length, Header header) {
        headerDecoder.wrap(buffer, offset);
        if (headerDecoder.schemaId() != MessageHeaderDecoder.SCHEMA_ID) {
            throw new IllegalStateException("unexpected schema " + headerDecoder.schemaId() + " in the cluster log");
        }
        switch (headerDecoder.templateId()) {
            case SessionMessageHeaderDecoder.TEMPLATE_ID -> {
                sessionHeaderDecoder.wrap(
                        buffer,
                        offset + MessageHeaderDecoder.ENCODED_LENGTH,
                        headerDecoder.blockLength(),
                        headerDecoder.version());
                listener.onSessionMessage(
                        header.position(),
                        sessionHeaderDecoder.timestamp(),
                        buffer,
                        offset + AeronCluster.SESSION_HEADER_LENGTH,
                        length - AeronCluster.SESSION_HEADER_LENGTH);
            }
            case TimerEventDecoder.TEMPLATE_ID -> {
                timerDecoder.wrap(
                        buffer,
                        offset + MessageHeaderDecoder.ENCODED_LENGTH,
                        headerDecoder.blockLength(),
                        headerDecoder.version());
                listener.onTimer(header.position(), timerDecoder.correlationId(), timerDecoder.timestamp());
            }
            default -> {} // session open/close, leadership terms, cluster actions: no state for the service
        }
        return ControlledFragmentHandler.Action.CONTINUE;
    }

    @Override
    public void close() {
        if (replaySessionId != Aeron.NULL_VALUE) {
            try {
                archive.stopReplay(replaySessionId);
            } catch (RuntimeException ignored) {
                // the replay may already have ended with the recording
            }
            replaySessionId = Aeron.NULL_VALUE;
        }
        CloseHelper.quietClose(subscription);
        subscription = null;
        image = null;
    }
}
