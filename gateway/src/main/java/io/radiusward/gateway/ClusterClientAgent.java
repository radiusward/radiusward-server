/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static io.radiusward.gateway.GatewayStats.Counter;

import io.aeron.cluster.client.AeronCluster;
import io.aeron.cluster.client.EgressListener;
import io.aeron.logbuffer.BufferClaim;
import io.aeron.logbuffer.Header;
import io.radiusward.protocol.AccountingCommittedDecoder;
import io.radiusward.protocol.AccountingRejectedDecoder;
import io.radiusward.protocol.MessageHeaderDecoder;
import org.agrona.CloseHelper;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.Agent;
import org.agrona.concurrent.ControlledMessageHandler;
import org.agrona.concurrent.ringbuffer.RingBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Owns the Aeron Cluster client (ADR 0011). Moves commands from the to-cluster ring buffer into the cluster
 * with {@code tryClaim} (no extra copy) and keeps polling egress even while the cluster backpressures or
 * elects a leader. Commit/reject notifications go back to the UDP agent through the from-cluster ring.
 *
 * <p>Connects asynchronously and reconnects after a lost session. Commands offered to a leader that died
 * before committing are not resent: the pending request times out and the NAS retransmission is submitted
 * again, which the cluster's dedup makes safe.
 */
final class ClusterClientAgent implements Agent, EgressListener {

    private static final Logger LOG = LogManager.getLogger(ClusterClientAgent.class);

    private static final long KEEP_ALIVE_INTERVAL_NS = 1_000_000_000L;
    private static final long RECONNECT_BACKOFF_NS = 500_000_000L;

    private final AeronCluster.Context template;
    private final RingBuffer toCluster;
    private final RingBuffer fromCluster;
    private final GatewayStats stats;
    private final BufferClaim claim = new BufferClaim();
    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final ControlledMessageHandler commandHandler = this::onCommand;

    private AeronCluster cluster;
    private AeronCluster.AsyncConnect connecting;
    private long lastSendNs;
    private long nextConnectNs;
    private long now;

    ClusterClientAgent(
            AeronCluster.Context template, RingBuffer toCluster, RingBuffer fromCluster, GatewayStats stats) {
        this.template = template.egressListener(this);
        this.toCluster = toCluster;
        this.fromCluster = fromCluster;
        this.stats = stats;
    }

    @Override
    public int doWork() {
        now = System.nanoTime();
        if (cluster == null) {
            return connect();
        }
        if (cluster.isClosed()) {
            LOG.warn("cluster session lost; reconnecting");
            stats.increment(Counter.CLUSTER_DISCONNECTS);
            stats.connected(false);
            CloseHelper.quietClose(cluster);
            cluster = null;
            nextConnectNs = now + RECONNECT_BACKOFF_NS;
            return 1;
        }
        int work = cluster.pollEgress();
        work += toCluster.controlledRead(commandHandler, 64);
        if (now - lastSendNs > KEEP_ALIVE_INTERVAL_NS && cluster.sendKeepAlive()) {
            lastSendNs = now;
        }
        return work;
    }

    private int connect() {
        if (now - nextConnectNs < 0) {
            return 0;
        }
        try {
            if (connecting == null) {
                connecting = AeronCluster.asyncConnect(template.clone());
            }
            AeronCluster connected = connecting.poll();
            if (connected != null) {
                connecting = null;
                cluster = connected;
                lastSendNs = now;
                stats.increment(Counter.CLUSTER_CONNECTS);
                stats.connected(true);
                LOG.info(
                        "connected to cluster, session {}, leader {}",
                        connected.clusterSessionId(),
                        connected.leaderMemberId());
            }
            return 1;
        } catch (RuntimeException e) {
            LOG.warn("cluster connect failed: {}", e.getMessage());
            CloseHelper.quietClose(connecting);
            connecting = null;
            nextConnectNs = now + RECONNECT_BACKOFF_NS;
            return 0;
        }
    }

    private ControlledMessageHandler.Action onCommand(int msgTypeId, DirectBuffer buffer, int index, int length) {
        long result = cluster.tryClaim(length, claim);
        if (result > 0) {
            claim.buffer().putBytes(claim.offset() + AeronCluster.SESSION_HEADER_LENGTH, buffer, index, length);
            claim.commit();
            lastSendNs = now;
            stats.increment(Counter.OFFERED);
            return ControlledMessageHandler.Action.COMMIT;
        }
        stats.increment(Counter.BACK_PRESSURED);
        return ControlledMessageHandler.Action.ABORT; // keep it in the ring and try again next duty cycle
    }

    @Override
    public void onMessage(
            long clusterSessionId, long timestamp, DirectBuffer buffer, int offset, int length, Header header) {
        headerDecoder.wrap(buffer, offset);
        if (headerDecoder.schemaId() != MessageHeaderDecoder.SCHEMA_ID) {
            return;
        }
        int msgType = switch (headerDecoder.templateId()) {
            case AccountingCommittedDecoder.TEMPLATE_ID -> UdpAgent.COMMITTED_MSG;
            case AccountingRejectedDecoder.TEMPLATE_ID -> UdpAgent.REJECTED_MSG;
            default -> 0;
        };
        if (msgType != 0 && !fromCluster.write(msgType, buffer, offset, length)) {
            stats.increment(Counter.RING_FULL); // the NAS retransmit will be answered as a duplicate
        }
    }

    @Override
    public void onNewLeader(long clusterSessionId, long leadershipTermId, int leaderMemberId, String ingressEndpoints) {
        LOG.info("new cluster leader {} (term {})", leaderMemberId, leadershipTermId);
    }

    boolean connected() {
        return cluster != null && !cluster.isClosed();
    }

    @Override
    public void onClose() {
        stats.connected(false);
        CloseHelper.quietCloseAll(connecting, cluster);
    }

    @Override
    public String roleName() {
        return "cluster-client";
    }
}
