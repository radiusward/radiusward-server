/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.aeron.cluster.client.AeronCluster;
import io.radiusward.protocol.MemberLogPositionEncoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import java.time.Duration;
import org.agrona.CloseHelper;
import org.agrona.concurrent.UnsafeBuffer;

/** Reports how far this member's own copy of the log reaches ({@code MemberLogPosition}); fire and forget. */
final class MemberReporter implements AutoCloseable {

    private final String aeronDir;
    private final String ingressEndpoints;
    private final String egressHost;
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[64]);
    private final MemberLogPositionEncoder encoder = new MemberLogPositionEncoder();
    private AeronCluster cluster;

    MemberReporter(String aeronDir, String ingressEndpoints, String egressHost) {
        this.aeronDir = aeronDir;
        this.ingressEndpoints = ingressEndpoints;
        this.egressHost = egressHost;
    }

    /** Returns whether the report was handed to the cluster. */
    boolean report(int memberId, long logPosition) {
        try {
            if (cluster == null || cluster.isClosed()) {
                cluster = AeronCluster.connect(new AeronCluster.Context()
                        .aeronDirectoryName(aeronDir)
                        .ingressChannel("aeron:udp")
                        .ingressEndpoints(ingressEndpoints)
                        .egressChannel("aeron:udp?endpoint=" + egressHost + ":0")
                        .messageTimeoutNs(Duration.ofSeconds(5).toNanos()));
            }
            encoder.wrapAndApplyHeader(buffer, 0, new MessageHeaderEncoder())
                    .memberId(memberId)
                    .logPosition(logPosition);
            int length = MessageHeaderEncoder.ENCODED_LENGTH + encoder.encodedLength();
            for (int attempt = 0; attempt < 100; attempt++) {
                cluster.pollEgress();
                if (cluster.offer(buffer, 0, length) > 0) {
                    return true;
                }
                java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
            }
            return false;
        } catch (RuntimeException e) {
            close();
            return false;
        }
    }

    @Override
    public void close() {
        CloseHelper.quietClose(cluster);
        cluster = null;
    }
}
