/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.gateway.EventKeys;
import io.radiusward.protocol.SessionStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.tools.admin.AdminClient;
import io.radiusward.tools.radclient.LoadGenerator;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The whole stack in one JVM: 3 cluster members (real Aeron, fsync) and 2 gateways (real UDP). */
class LocalClusterIT {

    static final byte[] SECRET = LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private LocalCluster cluster;
    private DatagramChannel nas;

    @AfterEach
    void close() throws IOException {
        if (nas != null) {
            nas.close();
        }
        if (cluster != null) {
            cluster.close();
        }
    }

    private LocalCluster start() {
        cluster = LocalCluster.start(dir.toFile(), 3, 2);
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        return cluster;
    }

    /**
     * Sends a request to a gateway and returns the verified response, retransmitting like a NAS: always from
     * the same source port, so the gateways' response caches see what they would see from a real NAS.
     */
    byte[] exchange(int port, byte[] request) throws IOException, InterruptedException {
        if (nas == null) {
            nas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
            nas.configureBlocking(false);
        }
        InetSocketAddress target = new InetSocketAddress("127.0.0.1", port);
        ByteBuffer in = ByteBuffer.allocate(4096);
        for (int attempt = 0; attempt < 8; attempt++) {
            nas.send(ByteBuffer.wrap(request), target);
            long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
            while (System.nanoTime() < deadline) {
                in.clear();
                if (nas.receive(in) != null) {
                    byte[] response = Arrays.copyOf(in.array(), in.position());
                    RadiusPacket view = new RadiusPacket();
                    view.wrap(new UnsafeBuffer(response), 0, response.length);
                    if (view.identifier() != (request[1] & 0xFF)) {
                        continue; // a late answer to an earlier request
                    }
                    assertThat(new RadiusAuthenticator().verifyResponse(view, new UnsafeBuffer(request), 4, SECRET))
                            .isTrue();
                    assertThat(view.code()).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
                    return response;
                }
                Thread.sleep(2);
            }
        }
        throw new AssertionError("no Accounting-Response");
    }

    static byte[] request(int id, int status, String sessionId, long sessionTime) {
        return request(id, status, sessionId, sessionTime, 1_780_000_000L);
    }

    static byte[] request(int id, int status, String sessionId, long sessionTime, long eventTimestamp) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id)
                .uint32(40, status)
                .attribute(44, sessionId)
                .uint32(55, eventTimestamp);
        if (status != 1) {
            enc.uint32(46, sessionTime).uint32(42, sessionTime * 1000);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    static long[] sessionKey(String sessionId) {
        EventKeys keys = new EventKeys();
        UnsafeBuffer id = new UnsafeBuffer(sessionId.getBytes(StandardCharsets.US_ASCII));
        keys.compute(LocalCluster.NAS_ID, 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
        return new long[] {keys.sessionHi(), keys.sessionLo()};
    }

    @Test
    void vendorFixturesAreAcknowledgedAndReplicated() throws Exception {
        start();
        int port = cluster.gateway(0).radiusPort();
        List<Path> fixtures;
        try (Stream<Path> walk = Files.walk(Path.of("../../radius-codec/src/test/resources/fixtures"))) {
            fixtures =
                    walk.filter(p -> p.toString().endsWith(".fixture")).sorted().toList();
        }
        for (Path fixture : fixtures) {
            for (String line : Files.readAllLines(fixture)) {
                if (line.startsWith("packet:")) {
                    exchange(port, HexFormat.of().parseHex(line.substring(7).trim()));
                }
            }
        }
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied()).isEqualTo(fixtures.size());
            assertThat(state.stopped())
                    .as("every fixture vendor ends with a Stop")
                    .isEqualTo(7);
            AdminClient.Session cisco = admin.session(sessionKey("00000A1B")[0], sessionKey("00000A1B")[1]);
            assertThat(cisco.status()).isEqualTo(SessionStatus.STOPPED);
            assertThat(cisco.sessionTime()).isEqualTo(7260);
            assertThat(cisco.outputOctets()).isEqualTo(13_958_643_712L);
        }
    }

    @Test
    void retransmitThroughTheOtherGatewayIsADuplicate() throws Exception {
        start();
        byte[] start = request(1, 1, "s-1", 0);
        exchange(cluster.gateway(0).radiusPort(), start);
        exchange(cluster.gateway(1).radiusPort(), start);
        exchange(cluster.gateway(0).radiusPort(), start); // gateway A answers from its cache
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied()).isEqualTo(1);
            assertThat(state.duplicates()).isEqualTo(1);
        }
        assertThat(cluster.gateway(0).stats().get(io.radiusward.gateway.GatewayStats.Counter.CACHE_HITS))
                .isEqualTo(1);
    }

    @Test
    void sessionWithoutStartAndLateStartAreAcknowledgedAndKeepTheProgress() throws Exception {
        start();
        long started = 1_780_000_000L;
        // the Start is lost on the way (or delayed): the first interim creates the session
        exchange(cluster.gateway(0).radiusPort(), request(1, 3, "s-4", 300, started + 300));
        // the delayed Start arrives after the interim, through the other gateway: acknowledged, merged
        byte[] lateStart = request(2, 1, "s-4", 0, started);
        exchange(cluster.gateway(1).radiusPort(), lateStart);
        exchange(cluster.gateway(0).radiusPort(), lateStart); // its retransmission is a duplicate
        // the interim retransmitted after the late Start is still a duplicate: the counters were not reset
        exchange(cluster.gateway(1).radiusPort(), request(3, 3, "s-4", 300, started + 300));
        exchange(cluster.gateway(0).radiusPort(), request(4, 3, "s-4", 600, started + 600));
        // a session that only ever sends interims and a Stop
        exchange(cluster.gateway(0).radiusPort(), request(5, 3, "s-5", 60, started + 60));
        exchange(cluster.gateway(0).radiusPort(), request(6, 2, "s-5", 120, started + 120));
        exchange(cluster.gateway(1).radiusPort(), request(7, 1, "s-5", 0, started)); // too late: stale

        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.Session s4 = admin.session(sessionKey("s-4")[0], sessionKey("s-4")[1]);
            assertThat(s4.status()).isEqualTo(SessionStatus.ACTIVE);
            assertThat(s4.statusType()).isEqualTo(3);
            assertThat(s4.sessionTime()).isEqualTo(600);
            assertThat(s4.inputOctets()).isEqualTo(600_000);
            AdminClient.Session s5 = admin.session(sessionKey("s-5")[0], sessionKey("s-5")[1]);
            assertThat(s5.status()).as("a late Start does not reopen it").isEqualTo(SessionStatus.STOPPED);
            assertThat(s5.sessionTime()).isEqualTo(120);
            AdminClient.State state = admin.state();
            assertThat(state.applied())
                    .as("interim, merged start, interim, interim, stop")
                    .isEqualTo(5);
            assertThat(state.duplicates()).isEqualTo(2);
            assertThat(state.stale()).isEqualTo(1);
            assertThat(state.active()).isEqualTo(1);
            assertThat(state.stopped()).isEqualTo(1);
        }
    }

    @Test
    void leaderLossDoesNotLoseAcknowledgedEvents() throws Exception {
        start();
        int port = cluster.gateway(0).radiusPort();
        exchange(port, request(1, 1, "s-2", 0));
        exchange(port, request(2, 3, "s-2", 60));
        ClusterNode leader = cluster.awaitLeader();
        int leaderId = leader.config().nodeId();
        cluster.stopNode(leaderId);

        exchange(port, request(3, 3, "s-2", 120)); // retransmitted until the new leader commits it
        exchange(port, request(4, 2, "s-2", 180));
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.Session session = admin.session(sessionKey("s-2")[0], sessionKey("s-2")[1]);
            assertThat(session.status()).isEqualTo(SessionStatus.STOPPED);
            assertThat(session.sessionTime()).isEqualTo(180);
            assertThat(admin.state().applied()).isEqualTo(4);
        }

        cluster.startNode(leaderId); // the old leader catches up as a follower
        cluster.awaitConverged();
        assertThat(cluster.node(leaderId).stats().applied()).isEqualTo(4);
    }

    @Test
    void dedupStateSurvivesSnapshotAndFullRestart() throws Exception {
        start();
        int port = cluster.gateway(0).radiusPort();
        byte[] start = request(1, 1, "s-3", 0);
        byte[] interim = request(2, 3, "s-3", 300);
        exchange(port, start);
        exchange(port, interim);
        cluster.awaitConverged();
        assertThat(cluster.awaitLeader().requestSnapshot()).isTrue();
        LocalCluster.await(
                Duration.ofSeconds(30),
                "snapshot on every member",
                () -> cluster.node(0).stats().snapshots() > 0
                        && cluster.node(1).stats().snapshots() > 0
                        && cluster.node(2).stats().snapshots() > 0);
        long digest = cluster.node(0).stats().digest();

        for (int i = 0; i < 3; i++) {
            cluster.stopNode(i);
        }
        for (int i = 0; i < 3; i++) {
            cluster.startNode(i);
        }
        cluster.awaitLeader();
        cluster.awaitConverged();
        assertThat(cluster.node(0).stats().digest()).isEqualTo(digest);

        // the gateway's cache does not know these (new identifiers), the cluster must
        exchange(port, request(9, 1, "s-3", 0));
        exchange(port, request(10, 3, "s-3", 300));
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied()).as("nothing applied twice").isEqualTo(2);
            // at least the two replays; a retransmit while the gateway reconnected may add a resubmission
            assertThat(state.duplicates()).isGreaterThanOrEqualTo(2);
            AdminClient.Session session = admin.session(sessionKey("s-3")[0], sessionKey("s-3")[1]);
            assertThat(session.status()).isEqualTo(SessionStatus.ACTIVE);
            assertThat(session.sessionTime()).isEqualTo(300);
        }
    }

    @Test
    void loadThroughBothGatewaysConverges() throws Exception {
        start();
        LoadGenerator.Result result = new LoadGenerator(
                        new LoadGenerator.Settings(
                                List.of(
                                        new InetSocketAddress(
                                                "127.0.0.1", cluster.gateway(0).radiusPort()),
                                        new InetSocketAddress(
                                                "127.0.0.1", cluster.gateway(1).radiusPort())),
                                SECRET,
                                5,
                                300,
                                1000,
                                Duration.ofSeconds(4),
                                Duration.ofSeconds(1),
                                Duration.ofSeconds(2),
                                3,
                                true,
                                true,
                                null),
                        new PrintStream(System.out))
                .run();
        assertThat(result.failed()).isZero();
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.stopped()).isEqualTo(300);
            assertThat(state.active()).isZero();
            assertThat(state.applied()).isLessThanOrEqualTo(result.sent());
        }
        String gatewayMetrics = cluster.gateway(0).metrics();
        io.radiusward.common.management.PrometheusWriter.validate(gatewayMetrics);
        assertThat(gatewayMetrics)
                .contains("radiusward_gateway_packets_total{gateway=\"1\",result=\"committed\"}")
                .contains("radiusward_gateway_cluster_connected{gateway=\"1\"} 1");
        String nodeMetrics = cluster.awaitLeader().metrics();
        io.radiusward.common.management.PrometheusWriter.validate(nodeMetrics);
        assertThat(nodeMetrics).contains("radiusward_sessions{member=").contains("radiusward_cluster_leader{");
    }
}
