/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.gateway.EventKeys;
import io.radiusward.gateway.NasRegistry;
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
@Epic("Accounting")
@Feature("Whole stack in one JVM")
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
            fixtures = walk.filter(p -> p.toString().endsWith(".fixture"))
                    // per vendor in the order a NAS sends them: the timestamps are fixed and old, so an Interim
                    // before its Start would be too old to create the session
                    .sorted(java.util.Comparator.comparing(
                                    (Path p) -> p.getParent().toString())
                            .thenComparing(p -> List.of("start.fixture", "interim.fixture", "stop.fixture")
                                    .indexOf(p.getFileName().toString())))
                    .toList();
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
                    .isEqualTo(fixtures.size() / 3);
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

        assertThat(cluster.gateway(1).ready().up()).isTrue();
        cluster.gateway(1).drain(); // SIGTERM with gateway.shutdown.drain: not ready, still answering
        assertThat(cluster.gateway(1).ready().detail()).isEqualTo("draining before shutdown");
        exchange(cluster.gateway(1).radiusPort(), request(1, 2, "s-2", 0));
    }

    @Test
    void sessionWithoutStartAndLateStartAreAcknowledgedAndKeepTheProgress() throws Exception {
        start();
        long started = System.currentTimeMillis() / 1000 - 1_800; // sessions that began half an hour ago
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
    void interimsInReverseOrderNeverMoveTheSessionBack() throws Exception {
        start();
        long started = System.currentTimeMillis() / 1000 - 1_800;
        int a = cluster.gateway(0).radiusPort();
        int b = cluster.gateway(1).radiusPort();
        // the NAS sent Start, 300, 600, 900, 1200, Stop at 1500; they arrive in this order, through both gateways
        exchange(a, request(1, 3, "s-6", 900, started + 900)); // creates the session
        exchange(b, request(2, 3, "s-6", 600, started + 600)); // older: stale
        exchange(a, request(3, 3, "s-6", 300, started + 300)); // older: stale
        exchange(b, request(4, 1, "s-6", 0, started)); // late Start: merged
        try (AdminClient admin = cluster.admin()) {
            AdminClient.Session s = admin.session(sessionKey("s-6")[0], sessionKey("s-6")[1]);
            assertThat(s.status()).isEqualTo(SessionStatus.ACTIVE);
            assertThat(s.sessionTime()).as("still the newest interim").isEqualTo(900);
            assertThat(s.inputOctets()).isEqualTo(900_000);
        }
        exchange(a, request(5, 2, "s-6", 1500, started + 1500)); // Stop before the last interim
        exchange(b, request(6, 3, "s-6", 1200, started + 1200)); // after the Stop: stale

        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.Session s = admin.session(sessionKey("s-6")[0], sessionKey("s-6")[1]);
            assertThat(s.status()).isEqualTo(SessionStatus.STOPPED);
            assertThat(s.statusType()).isEqualTo(2);
            assertThat(s.sessionTime()).isEqualTo(1500);
            assertThat(s.inputOctets()).isEqualTo(1_500_000);
            AdminClient.State state = admin.state();
            assertThat(state.applied()).as("interim 900, merged start, stop").isEqualTo(3);
            assertThat(state.stale()).as("interims 600, 300 and 1200").isEqualTo(3);
            assertThat(state.duplicates()).isZero();
        }
    }

    @Test
    void interimOlderThanTheTombstoneWindowDoesNotCreateASession() throws Exception {
        start();
        long now = System.currentTimeMillis() / 1000;
        // an Interim held back by the NAS for 2 h (tombstone window 1 h): its session may have been stopped and
        // forgotten meanwhile, so it must not come back as an active session
        exchange(cluster.gateway(0).radiusPort(), request(1, 3, "s-7", 600, now - 7_200));
        // a recent Interim whose Start was lost still creates its session
        exchange(cluster.gateway(1).radiusPort(), request(2, 3, "s-8", 600, now - 60));

        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            assertThat(admin.session(sessionKey("s-7")[0], sessionKey("s-7")[1]).status())
                    .as("acknowledged, kept as stale history only")
                    .isEqualTo(SessionStatus.UNKNOWN);
            assertThat(admin.session(sessionKey("s-8")[0], sessionKey("s-8")[1]).status())
                    .isEqualTo(SessionStatus.ACTIVE);
            AdminClient.State state = admin.state();
            assertThat(state.applied()).isEqualTo(1);
            assertThat(state.stale()).isEqualTo(1);
            assertThat(state.active()).isEqualTo(1);
        }
    }

    @Test
    void devicesBehindOneAddressKeepTheirSessionsApart() throws Exception {
        cluster = LocalCluster.start(dir.toFile(), 3, 0);
        NasRegistry byDevice = LocalCluster.registry(io.radiusward.gateway.NasClient.Identity.NAS_IDENTIFIER);
        cluster.startGateway(1, 0, byDevice);
        cluster.startGateway(2, 0, byDevice);
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        Path ackLog = dir.resolve("acks.csv");
        // 50 access points behind one address, each numbering its 10 sessions 00000000..00000009
        LoadGenerator.Result result = new LoadGenerator(
                        new LoadGenerator.Settings(
                                List.of(
                                        new InetSocketAddress(
                                                "127.0.0.1", cluster.gateway(0).radiusPort()),
                                        new InetSocketAddress(
                                                "127.0.0.1", cluster.gateway(1).radiusPort())),
                                SECRET,
                                50,
                                500,
                                1000,
                                Duration.ofSeconds(5),
                                Duration.ofSeconds(2),
                                Duration.ofSeconds(2),
                                3,
                                true,
                                false,
                                ackLog,
                                0,
                                true),
                        new PrintStream(System.out))
                .run();
        assertThat(result.failed()).isZero();
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            assertThat(admin.state().active())
                    .as("500 sessions, though only 10 distinct ids")
                    .isEqualTo(500);
            assertThat(io.radiusward.tools.admin.AckVerifier.verify(ackLog, LocalCluster.NAS_ID, true, admin::session)
                            .lost())
                    .isEmpty();
        }

        // access point nas3 reboots: only its 10 sessions stop
        exchange(cluster.gateway(0).radiusPort(), accountingOn(1, "nas3"));
        // an Accounting-On without NAS-Identifier is acknowledged, but cannot say whose sessions to stop
        exchange(cluster.gateway(1).radiusPort(), accountingOn(2, null));
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.active()).isEqualTo(490);
            assertThat(state.stopped()).isEqualTo(10);
        }
        assertThat(cluster.gateway(1).stats().get(io.radiusward.gateway.GatewayStats.Counter.IDENTITY_MISSING))
                .isEqualTo(1);
        assertThat(cluster.awaitLeader().stats().identityMismatches()).isZero();
    }

    static byte[] accountingOn(int id, String nasIdentifier) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id).uint32(40, 7).uint32(55, System.currentTimeMillis() / 1000);
        if (nasIdentifier != null) {
            enc.attribute(32, nasIdentifier);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    @Test
    void membersReportTheirStateVersionAndActivationIsGated() throws Exception {
        int supported = io.radiusward.cluster.service.AccountingStateMachine.STATE_VERSION;
        cluster = LocalCluster.start(
                dir.toFile(),
                3,
                1,
                LocalCluster.freePortBase(3),
                new int[1],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)));
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        exchange(cluster.gateway(0).radiusPort(), request(1, 1, "s-9", 0)); // the log needs a recording to report
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "every member reported its supported version",
                    () -> admin.state().lowestSupportedVersion() == supported);
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "every member runs it: activated automatically",
                    () -> admin.state().activeVersion() == supported);
            assertThat(supported).isGreaterThan(io.radiusward.cluster.service.StateVersions.BASELINE);
            assertThat(admin.activateVersion(supported).result())
                    .as("already active")
                    .isEqualTo(io.radiusward.protocol.ActivationResult.NOT_NEWER);
            AdminClient.Activation future = admin.activateVersion(supported + 1);
            assertThat(future.result())
                    .as("no member runs code that knows it")
                    .isEqualTo(io.radiusward.protocol.ActivationResult.MEMBERS_NOT_READY);
            assertThat(future.lowestSupportedVersion()).isEqualTo(supported);
        }
        String metrics = cluster.awaitLeader().metrics();
        io.radiusward.common.management.PrometheusWriter.validate(metrics);
        assertThat(metrics)
                .containsPattern("radiusward_state_version\\{member=\"\\d\",kind=\"active\"\\} " + supported)
                .contains("radiusward_state_version_held{");
        assertThat(cluster.awaitLeader().stateJson()).contains("\"stateVersionActive\":" + supported);

        // a member restarted from the log applies the same version
        cluster.stopNode(2);
        cluster.startNode(2);
        cluster.awaitConverged();
        assertThat(cluster.node(2).stats().activeVersion()).isEqualTo(supported);
        assertThat(cluster.node(2).stats().fatal()).isNull();
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
