/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import static org.assertj.core.api.Assertions.assertThat;

import io.aeron.cluster.client.AeronCluster;
import io.aeron.cluster.client.EgressListener;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import io.aeron.logbuffer.Header;
import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.common.Profile;
import io.radiusward.exporter.ExportConfig;
import io.radiusward.protocol.AccountingCommandEncoder;
import io.radiusward.protocol.AccountingCommittedDecoder;
import io.radiusward.protocol.AccountingRejectedDecoder;
import io.radiusward.protocol.ExportCheckpointAckDecoder;
import io.radiusward.protocol.ExportCheckpointEncoder;
import io.radiusward.protocol.LeaseResult;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.OnMaxLag;
import io.radiusward.protocol.Outcome;
import io.radiusward.protocol.RejectReason;
import java.io.File;
import java.net.DatagramSocket;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import org.agrona.CloseHelper;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Three real cluster members in one JVM: commit, snapshot, leader loss and re-election. */
class ThreeNodeClusterIT {

    @TempDir
    Path dir;

    private final ClusterNode[] byId = new ClusterNode[3];
    private MediaDriver clientDriver;
    private AeronCluster client;
    private final Map<Long, Outcome> outcomes = new ConcurrentHashMap<>();
    private final Map<Long, RejectReason> rejections = new ConcurrentHashMap<>();
    private final Map<Long, Ack> acks = new ConcurrentHashMap<>();
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[1024]);
    private int basePort;

    @AfterEach
    void tearDown() {
        CloseHelper.quietCloseAll(client, clientDriver);
        for (ClusterNode node : byId) {
            CloseHelper.quietClose(node);
        }
    }

    private ClusterNodeConfig config(int id) {
        return new ClusterNodeConfig(
                id,
                List.of("localhost", "localhost", "localhost"),
                basePort,
                new File(dir.toFile(), "data/node-" + id),
                new File(dir.toFile(), "aeron-" + id).getPath(),
                Profile.SMALL,
                Duration.ofMillis(1500),
                Duration.ofMillis(500),
                Duration.ofSeconds(10),
                Duration.ZERO,
                2,
                id == 2 ? Long.MAX_VALUE / 2 : 1, // node 2 never has enough disk space: reports not ready
                256,
                AccountingStateMachine.Settings.defaults(1000),
                Duration.ofSeconds(60),
                ExportConfig.NONE,
                LogPurgeConfig.DEFAULTS);
    }

    @Test
    void commitSnapshotAndFailover() throws Exception {
        basePort = freePortBase();
        for (int i = 0; i < 3; i++) {
            byId[i] = ClusterNode.launch(config(i), null);
        }
        ClusterNode leader = awaitLeader(null);

        clientDriver = MediaDriver.launchEmbedded(new MediaDriver.Context()
                .threadingMode(ThreadingMode.SHARED)
                .dirDeleteOnStart(true)
                .dirDeleteOnShutdown(true)
                .aeronDirectoryName(new File(dir.toFile(), "aeron-client").getPath()));
        connectClient();

        assertThat(send(1, 100, AccountingStateMachine.STATUS_START, 0)).isEqualTo(Outcome.APPLIED);
        assertThat(send(2, 100, AccountingStateMachine.STATUS_START, 0)).isEqualTo(Outcome.DUPLICATE);
        assertThat(send(3, 100, AccountingStateMachine.STATUS_INTERIM, 300)).isEqualTo(Outcome.APPLIED);
        await(() -> allDigestsEqual(3), "replicas converge");

        assertThat(leader.requestSnapshot()).isTrue();
        await(() -> live().stream().allMatch(n -> n.stats().snapshots() >= 1), "all members snapshot");

        int oldLeader = leader.config().nodeId();
        byId[oldLeader].close();
        byId[oldLeader] = null;
        ClusterNode newLeader = awaitLeader(oldLeader);
        assertThat(newLeader.config().nodeId()).isNotEqualTo(oldLeader);

        Outcome afterFailover = null;
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (afterFailover == null && System.nanoTime() < deadline) {
            if (client == null || client.isClosed()) {
                connectClient();
            }
            afterFailover = trySend(4, 100, AccountingStateMachine.STATUS_INTERIM, 600, Duration.ofSeconds(2));
        }
        assertThat(afterFailover).isEqualTo(Outcome.APPLIED);
        assertThat(send(5, 100, AccountingStateMachine.STATUS_INTERIM, 600)).isEqualTo(Outcome.DUPLICATE);
        await(() -> allDigestsEqual(2), "remaining replicas converge");
        assertThat(newLeader.stats().applied()).isEqualTo(3);
        assertThat(newLeader.stateJson()).contains("\"role\":\"LEADER\"").contains("\"applied\":3");
        for (ClusterNode n : live()) {
            int id = n.config().nodeId();
            assertThat(n.ready().up()).as("node %d ready", id).isEqualTo(id != 2);
            if (id == 2) {
                assertThat(n.ready().detail()).startsWith("low disk space");
            }
        }
        assertThat(newLeader.stateJson()).contains("\"diskFreeBytes\":");

        // export leases and the lag policy, decided by the replicated state (ADR 0017)
        Ack first = checkpoint(100, "pg", 0, 0, 0, 10_000, 0);
        assertThat(first.result).isEqualTo(LeaseResult.GRANTED);
        assertThat(first.owner).isZero();
        assertThat(first.epoch).isEqualTo(1);
        assertThat(checkpoint(101, "pg", 1, 0, 0, 10_000, 0).result).isEqualTo(LeaseResult.NOT_OWNER);
        assertThat(checkpoint(102, "pg", 0, 1, 0, 1, 0).result)
                .as("renew with a 1 ms lease")
                .isEqualTo(LeaseResult.GRANTED);
        Thread.sleep(50);
        Ack takeover = checkpoint(103, "pg", 1, 0, 0, 10_000, 0);
        assertThat(takeover.result).isEqualTo(LeaseResult.GRANTED);
        assertThat(takeover.owner).isEqualTo(1);
        assertThat(takeover.epoch).as("new epoch on takeover").isEqualTo(2);

        // a required sink far behind (limit 1 byte) blocks new accounting until it checkpoints again
        assertThat(checkpoint(104, "pg", 1, 2, 0, 10_000, 1).result).isEqualTo(LeaseResult.GRANTED);
        assertThat(trySend(6, 200, AccountingStateMachine.STATUS_START, 0, Duration.ofSeconds(2)))
                .as("no ACK while the sink is over its limit")
                .isNull();
        assertThat(rejections.get(6L)).isEqualTo(RejectReason.EXPORT_LAG);
        assertThat(checkpoint(105, "pg", 1, 2, Long.MAX_VALUE / 2, 10_000, 0).result)
                .isEqualTo(LeaseResult.GRANTED);
        assertThat(send(7, 200, AccountingStateMachine.STATUS_START, 0)).isEqualTo(Outcome.APPLIED);
        await(() -> allDigestsEqual(2), "replicas agree after the export commands");
        String metrics = byId[
                takeover.owner == 1 && byId[1] != null ? 1 : newLeader.config().nodeId()].metrics();
        io.radiusward.common.management.PrometheusWriter.validate(metrics);
        assertThat(metrics)
                .contains("radiusward_accounting_events_total{member=")
                .contains("radiusward_accounting_export_lag_rejections_total")
                .contains("radiusward_jvm_memory_used_bytes");
    }

    private record Ack(LeaseResult result, int owner, long epoch) {}

    private Ack checkpoint(
            long correlationId, String sink, int member, long epoch, long position, long leaseMs, long maxLagBytes)
            throws InterruptedException {
        byte[] name = new byte[32];
        byte[] ascii = sink.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(ascii, 0, name, 0, ascii.length);
        ExportCheckpointEncoder encoder = new ExportCheckpointEncoder();
        encoder.wrapAndApplyHeader(buffer, 0, new MessageHeaderEncoder())
                .correlationId(correlationId)
                .putSinkName(name, 0)
                .memberId(member)
                .epoch(epoch)
                .position(position)
                .lastEventTime(0)
                .leaseTimeoutMs(leaseMs)
                .required((short) 1)
                .maxLagBytes(maxLagBytes)
                .maxLagMs(0)
                .onMaxLag(OnMaxLag.BLOCK);
        int length = MessageHeaderEncoder.ENCODED_LENGTH + encoder.encodedLength();
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        boolean sent = false;
        while (System.nanoTime() < deadline) {
            if (!sent) {
                sent = client.offer(buffer, 0, length) > 0;
            }
            client.pollEgress();
            Ack ack = acks.get(correlationId);
            if (ack != null) {
                return ack;
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("no checkpoint ack for " + correlationId);
    }

    private void connectClient() {
        CloseHelper.quietClose(client);
        client = AeronCluster.connect(new AeronCluster.Context()
                .aeronDirectoryName(clientDriver.aeronDirectoryName())
                .ingressChannel("aeron:udp")
                .ingressEndpoints(
                        ClusterNodeConfig.ingressEndpoints(List.of("localhost", "localhost", "localhost"), basePort))
                .egressChannel("aeron:udp?endpoint=localhost:0")
                .messageTimeoutNs(Duration.ofSeconds(10).toNanos())
                .egressListener(new Listener()));
    }

    final class Listener implements EgressListener {
        private final MessageHeaderDecoder header = new MessageHeaderDecoder();
        private final AccountingCommittedDecoder committed = new AccountingCommittedDecoder();
        private final AccountingRejectedDecoder rejected = new AccountingRejectedDecoder();
        private final ExportCheckpointAckDecoder ack = new ExportCheckpointAckDecoder();

        @Override
        public void onMessage(long sessionId, long timestamp, DirectBuffer buf, int offset, int length, Header h) {
            header.wrap(buf, offset);
            if (header.templateId() == AccountingCommittedDecoder.TEMPLATE_ID) {
                committed.wrapAndApplyHeader(buf, offset, header);
                outcomes.put(committed.correlationId(), committed.outcome());
            } else if (header.templateId() == AccountingRejectedDecoder.TEMPLATE_ID) {
                rejected.wrapAndApplyHeader(buf, offset, header);
                rejections.put(rejected.correlationId(), rejected.reason());
            } else if (header.templateId() == ExportCheckpointAckDecoder.TEMPLATE_ID) {
                ack.wrapAndApplyHeader(buf, offset, header);
                acks.put(ack.correlationId(), new Ack(ack.result(), ack.owner(), ack.epoch()));
            }
        }
    }

    private Outcome send(long correlationId, long session, int status, long sessionTime) {
        Outcome outcome = trySend(correlationId, session, status, sessionTime, Duration.ofSeconds(10));
        assertThat(outcome).as("committed reply for %d", correlationId).isNotNull();
        return outcome;
    }

    private Outcome trySend(long correlationId, long session, int status, long sessionTime, Duration timeout) {
        AccountingCommandEncoder encoder = new AccountingCommandEncoder();
        encoder.wrapAndApplyHeader(buffer, 0, new MessageHeaderEncoder())
                .correlationId(correlationId)
                .gatewayId(1)
                .nasId(7)
                .sessionKeyHi(session)
                .sessionKeyLo(session)
                .exactKeyHi(session * 31 + status)
                .exactKeyLo(sessionTime)
                .statusType(status)
                .sessionTime(sessionTime)
                .eventTimestamp(0)
                .inputOctets(sessionTime * 100)
                .outputOctets(0);
        encoder.flags().clear().sessionTimePresent(true);
        encoder.sessionId("s" + session);
        encoder.putRawAttributes(new byte[0], 0, 0);
        int length = MessageHeaderEncoder.ENCODED_LENGTH + encoder.encodedLength();
        long deadline = System.nanoTime() + timeout.toNanos();
        boolean sent = false;
        while (System.nanoTime() < deadline) {
            if (client.isClosed()) {
                return null;
            }
            if (!sent) {
                sent = client.offer(buffer, 0, length) > 0;
            }
            client.pollEgress();
            Outcome outcome = outcomes.get(correlationId);
            if (outcome != null) {
                return outcome;
            }
            Thread.onSpinWait();
        }
        return null;
    }

    private List<ClusterNode> live() {
        List<ClusterNode> live = new ArrayList<>();
        for (ClusterNode n : byId) {
            if (n != null) {
                live.add(n);
            }
        }
        return live;
    }

    private boolean allDigestsEqual(int expectedMembers) {
        List<ClusterNode> live = live();
        if (live.size() != expectedMembers) {
            return false;
        }
        long digest = live.get(0).stats().digest();
        long applied = live.get(0).stats().applied();
        return applied > 0
                && live.stream()
                        .allMatch(n -> n.stats().digest() == digest && n.stats().applied() == applied);
    }

    private ClusterNode awaitLeader(Integer notId) throws InterruptedException {
        ClusterNode[] found = new ClusterNode[1];
        await(
                () -> {
                    for (ClusterNode n : live()) {
                        if ("LEADER".equals(n.stats().role())
                                && (notId == null || n.config().nodeId() != notId)) {
                            found[0] = n;
                            return true;
                        }
                    }
                    return false;
                },
                "leader elected");
        return found[0];
    }

    private static void await(BooleanSupplier condition, String what) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out waiting for: " + what);
            }
            Thread.sleep(50);
        }
    }

    /** A base port where all 3 × 6 UDP ports are currently free. */
    static int freePortBase() {
        for (int attempt = 0; attempt < 50; attempt++) {
            int base = 20_000 + (int) (Math.random() * 120) * 100; // below the ephemeral port ranges
            if (allFree(base)) {
                return base;
            }
        }
        throw new IllegalStateException("no free port range");
    }

    private static boolean allFree(int base) {
        for (int i = 0; i < 3; i++) {
            for (int o = 0; o < 6; o++) {
                try (DatagramSocket s = new DatagramSocket(base + 100 * i + o)) {
                    s.setReuseAddress(false);
                } catch (Exception e) {
                    return false;
                }
            }
        }
        return true;
    }
}
