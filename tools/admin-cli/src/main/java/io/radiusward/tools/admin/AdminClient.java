/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import io.aeron.cluster.client.AeronCluster;
import io.aeron.cluster.client.EgressListener;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import io.aeron.logbuffer.Header;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.SessionQueryEncoder;
import io.radiusward.protocol.SessionReportDecoder;
import io.radiusward.protocol.SessionStatus;
import io.radiusward.protocol.StateQueryEncoder;
import io.radiusward.protocol.StateReportDecoder;
import java.io.File;
import java.nio.file.Files;
import java.time.Duration;
import java.util.List;
import org.agrona.CloseHelper;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Queries the replicated state through the cluster log ({@code StateQuery}, {@code SessionQuery}), so answers
 * reflect everything committed before the query. For tests and tooling; not used by the gateways.
 *
 * <p>The egress host must be an address of this machine that the cluster members can reach: {@code localhost}
 * when they run on the same host, the container IP inside a Docker network.
 */
public final class AdminClient implements AutoCloseable, EgressListener {

    /** State totals as replicated. */
    public record State(
            long applied, long duplicates, long stale, long rejected, long active, long stopped, long digest) {}

    /** One session as replicated. */
    public record Session(
            SessionStatus status,
            int nasId,
            long statusType,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets) {}

    private final MediaDriver driver;
    private final AeronCluster cluster;
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final StateReportDecoder stateDecoder = new StateReportDecoder();
    private final SessionReportDecoder sessionDecoder = new SessionReportDecoder();
    private long correlation;
    private Object reply;
    private long replyCorrelation;

    public AdminClient(List<String> members, int basePort) {
        this(members, basePort, "localhost");
    }

    public AdminClient(List<String> members, int basePort, String egressHost) {
        try {
            File dir = Files.createTempDirectory("radiusward-admin").toFile();
            driver = MediaDriver.launchEmbedded(new MediaDriver.Context()
                    .aeronDirectoryName(new File(dir, "aeron").getPath())
                    .threadingMode(ThreadingMode.SHARED)
                    .publicationTermBufferLength(1 << 20)
                    .ipcTermBufferLength(1 << 20)
                    .dirDeleteOnStart(true)
                    .dirDeleteOnShutdown(true));
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
        StringBuilder endpoints = new StringBuilder();
        for (int i = 0; i < members.size(); i++) {
            endpoints
                    .append(i == 0 ? "" : ",")
                    .append(i)
                    .append('=')
                    .append(members.get(i))
                    .append(':')
                    .append(basePort + 100 * i);
        }
        cluster = AeronCluster.connect(new AeronCluster.Context()
                .aeronDirectoryName(driver.aeronDirectoryName())
                .ingressChannel("aeron:udp?term-length=1m")
                .ingressEndpoints(endpoints.toString())
                .egressChannel("aeron:udp?endpoint=" + egressHost + ":0")
                .messageTimeoutNs(Duration.ofSeconds(20).toNanos())
                .egressListener(this));
    }

    public State state() {
        long id = ++correlation;
        new StateQueryEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(id);
        return (State) request(id, MessageHeaderEncoder.ENCODED_LENGTH + StateQueryEncoder.BLOCK_LENGTH);
    }

    public Session session(long keyHi, long keyLo) {
        long id = ++correlation;
        new SessionQueryEncoder()
                .wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(id)
                .sessionKeyHi(keyHi)
                .sessionKeyLo(keyLo);
        return (Session) request(id, MessageHeaderEncoder.ENCODED_LENGTH + SessionQueryEncoder.BLOCK_LENGTH);
    }

    private Object request(long id, int length) {
        reply = null;
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (cluster.offer(buffer, 0, length) < 0) {
            cluster.pollEgress();
            check(deadline);
        }
        while (reply == null || replyCorrelation != id) {
            cluster.pollEgress();
            check(deadline);
            Thread.onSpinWait();
        }
        return reply;
    }

    private static void check(long deadline) {
        if (System.nanoTime() > deadline) {
            throw new IllegalStateException("no reply from the cluster");
        }
    }

    @Override
    public void onMessage(long sessionId, long timestamp, DirectBuffer buf, int offset, int length, Header header) {
        headerDecoder.wrap(buf, offset);
        if (headerDecoder.templateId() == StateReportDecoder.TEMPLATE_ID) {
            stateDecoder.wrapAndApplyHeader(buf, offset, headerDecoder);
            replyCorrelation = stateDecoder.correlationId();
            reply = new State(
                    stateDecoder.applied(),
                    stateDecoder.duplicates(),
                    stateDecoder.stale(),
                    stateDecoder.rejected(),
                    stateDecoder.activeSessions(),
                    stateDecoder.stoppedSessions(),
                    stateDecoder.stateDigest());
        } else if (headerDecoder.templateId() == SessionReportDecoder.TEMPLATE_ID) {
            sessionDecoder.wrapAndApplyHeader(buf, offset, headerDecoder);
            replyCorrelation = sessionDecoder.correlationId();
            reply = new Session(
                    sessionDecoder.status(),
                    sessionDecoder.nasId(),
                    sessionDecoder.statusType(),
                    sessionDecoder.sessionTime(),
                    sessionDecoder.eventTimestamp(),
                    sessionDecoder.inputOctets(),
                    sessionDecoder.outputOctets());
        }
    }

    @Override
    public void close() {
        CloseHelper.quietCloseAll(cluster, driver);
    }
}
