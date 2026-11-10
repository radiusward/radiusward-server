/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.aeron.cluster.client.AeronCluster;
import io.aeron.cluster.client.EgressListener;
import io.aeron.logbuffer.Header;
import io.radiusward.protocol.ExportCheckpointAckDecoder;
import io.radiusward.protocol.ExportCheckpointEncoder;
import io.radiusward.protocol.LeaseResult;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.OnMaxLag;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.agrona.CloseHelper;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Sends {@code ExportCheckpoint} commands through the cluster's ingress and waits for the
 * {@code ExportCheckpointAck}. The checkpoint is part of the replicated state, so the cluster (not this
 * member) decides who holds a sink's lease. Reconnects lazily; one instance per sink thread.
 */
public final class LeaseClient implements AutoCloseable, EgressListener {

    private static final org.apache.logging.log4j.Logger LOG =
            org.apache.logging.log4j.LogManager.getLogger(LeaseClient.class);

    /**
     * The error handler of the exporter's Aeron clients: logged. Aeron's default exits the JVM when the media driver
     * goes away, which a member's own shutdown does.
     */
    static final org.agrona.ErrorHandler LOG_ERRORS = t -> LOG.warn("exporter Aeron client: {}", t.toString());

    /** The cluster's answer. */
    public record Ack(LeaseResult result, int owner, long epoch, long checkpoint, boolean detached, boolean resync) {}

    private final String aeronDir;
    private final String ingressEndpoints;
    private final String egressHost;
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final ExportCheckpointEncoder encoder = new ExportCheckpointEncoder();
    private final ExportCheckpointAckDecoder ackDecoder = new ExportCheckpointAckDecoder();
    private final byte[] name = new byte[32];
    private AeronCluster cluster;
    private long correlationId;
    private Ack ack;
    private long ackCorrelation;

    public LeaseClient(String aeronDir, String ingressEndpoints, String egressHost) {
        this.aeronDir = aeronDir;
        this.ingressEndpoints = ingressEndpoints;
        this.egressHost = egressHost;
    }

    /** Sends a checkpoint (or claim with {@code epoch} 0) and returns the answer, or {@code null} on timeout. */
    public Ack checkpoint(
            SinkConfig sink, int memberId, long epoch, long position, long lastEventTime, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        try {
            connect();
            long id = ++correlationId;
            byte[] ascii = sink.name().getBytes(StandardCharsets.US_ASCII);
            java.util.Arrays.fill(name, (byte) 0);
            System.arraycopy(ascii, 0, name, 0, Math.min(ascii.length, name.length));
            encoder.wrapAndApplyHeader(buffer, 0, headerEncoder)
                    .correlationId(id)
                    .putSinkName(name, 0)
                    .memberId(memberId)
                    .epoch(epoch)
                    .position(position)
                    .lastEventTime(lastEventTime)
                    .leaseTimeoutMs(sink.leaseTimeoutMs())
                    .required((short) (sink.required() ? 1 : 0))
                    .maxLagBytes(sink.maxLagBytes())
                    .maxLagMs(sink.maxLagMs())
                    .onMaxLag(sink.detachOnMaxLag() ? OnMaxLag.DETACH : OnMaxLag.BLOCK);
            int length = MessageHeaderEncoder.ENCODED_LENGTH + encoder.encodedLength();
            ack = null;
            boolean sent = false;
            while (System.nanoTime() < deadline) {
                if (cluster.isClosed()) {
                    close();
                    return null;
                }
                if (!sent) {
                    sent = cluster.offer(buffer, 0, length) > 0;
                }
                if (cluster.pollEgress() == 0) {
                    if (ack != null && ackCorrelation == id) {
                        return ack;
                    }
                    java.util.concurrent.locks.LockSupport.parkNanos(50_000); // never spin: shares the member's CPU
                }
                if (ack != null && ackCorrelation == id) {
                    return ack;
                }
            }
            return null;
        } catch (RuntimeException e) {
            close(); // e.g. no leader yet; the caller retries
            return null;
        }
    }

    private void connect() {
        if (cluster != null && !cluster.isClosed()) {
            return;
        }
        cluster = AeronCluster.connect(new AeronCluster.Context()
                .aeronDirectoryName(aeronDir)
                .errorHandler(LOG_ERRORS)
                .ingressChannel("aeron:udp")
                .ingressEndpoints(ingressEndpoints)
                .egressChannel("aeron:udp?endpoint=" + egressHost + ":0")
                .messageTimeoutNs(Duration.ofSeconds(5).toNanos())
                .egressListener(this));
    }

    @Override
    public void onMessage(long sessionId, long timestamp, DirectBuffer buf, int offset, int length, Header header) {
        headerDecoder.wrap(buf, offset);
        if (headerDecoder.schemaId() == MessageHeaderDecoder.SCHEMA_ID
                && headerDecoder.templateId() == ExportCheckpointAckDecoder.TEMPLATE_ID) {
            ackDecoder.wrapAndApplyHeader(buf, offset, headerDecoder);
            ackCorrelation = ackDecoder.correlationId();
            ack = new Ack(
                    ackDecoder.result(),
                    ackDecoder.owner(),
                    ackDecoder.epoch(),
                    ackDecoder.checkpoint(),
                    ackDecoder.detached() != 0,
                    ackDecoder.resync() != 0);
        }
    }

    @Override
    public void close() {
        CloseHelper.quietClose(cluster);
        cluster = null;
    }
}
