/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.gateway.AccessHandler;
import io.radiusward.gateway.AuthConfig;
import io.radiusward.gateway.Gateway;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.tools.admin.AdminClient;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * SIM sequence numbers through the cluster (state version 8, ADR 0061): an access handler asks for the next SQN of a
 * subscriber and answers with it. Two gateways share one sequence, a floor lifts it, and a new leader continues it.
 */
@Epic("EAP")
@Feature("SIM sequence numbers")
@Link(name = "ADR 0061", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0061-eap-sim-aka.md")
class SqnIT {

    static final byte[] SECRET = LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private LocalCluster cluster;
    private DatagramChannel nas;
    private int identifier;

    @AfterEach
    void stop() throws Exception {
        if (nas != null) {
            nas.close();
        }
        if (cluster != null) {
            cluster.close();
        }
    }

    /** User-Name is the subscriber, User-Password the floor; the SQN comes back as the Reply-Message. */
    static AccessHandler sqnHandler() {
        UnsafeBuffer password = new UnsafeBuffer(new byte[128]);
        return context -> {
            RadiusPacket request = context.request();
            int at = request.findAttribute(1);
            String user = request.buffer()
                    .getStringWithoutLengthAscii(at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
            int n = context.credentials()
                    .decryptUserPassword(request, context.nas().secret(), password, 0);
            long floor =
                    Long.parseLong(password.getStringWithoutLengthAscii(0, n).trim());
            long sqn = context.sessionLimits().nextSqn(user.hashCode(), floor);
            if (sqn < 0) {
                return AccessHandler.DROP;
            }
            context.reply().attribute(18, Long.toString(sqn));
            return AccessHandler.ACCEPT;
        };
    }

    @Test
    void oneSequencePerSubscriberAcrossGatewaysAndALeaderChange() throws Exception {
        cluster = LocalCluster.start(
                dir.resolve("cluster").toFile(),
                3,
                0,
                LocalCluster.freePortBase(3),
                new int[0],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)));
        AuthConfig auth = new AuthConfig(
                true, 0, 2, 256, 4096, Duration.ofSeconds(10), Duration.ofSeconds(2), Duration.ofSeconds(30));
        Gateway g0 = cluster.startGateway(1, 0, LocalCluster.registry(), auth, d -> sqnHandler());
        Gateway g1 = cluster.startGateway(2, 0, LocalCluster.registry(), auth, d -> sqnHandler());
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        exchange(g0.radiusPort(), warmUp()); // the log needs a recording before members report their versions
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "state version 8 activated",
                    () -> admin.state().activeVersion() >= 8);
        }

        assertThat(sqn(g0, "262011000000001", 0)).isEqualTo(32);
        assertThat(sqn(g1, "262011000000001", 0))
                .as("the other gateway goes on")
                .isEqualTo(64);
        assertThat(sqn(g0, "262011000000002", 0)).as("another subscriber").isEqualTo(32);
        assertThat(sqn(g1, "262011000000001", 4000))
                .as("a resynchronised floor")
                .isEqualTo(4032);

        ClusterNode leader = cluster.awaitLeader();
        cluster.stopNode(leader.config().nodeId());
        assertThat(sqn(g0, "262011000000001", 0))
                .as("the new leader continues, nothing reused")
                .isEqualTo(4064);
    }

    private long sqn(Gateway gateway, String imsi, long floor) throws Exception {
        byte[] auth = new byte[16];
        ThreadLocalRandom.current().nextBytes(auth);
        byte[] plain = Long.toString(floor).getBytes(StandardCharsets.US_ASCII);
        UnsafeBuffer cipher = new UnsafeBuffer(new byte[128]);
        int n = new AccessRequests()
                .encryptUserPassword(
                        new UnsafeBuffer(plain), 0, plain.length, new UnsafeBuffer(auth), 0, SECRET, cipher, 0);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, ++identifier & 0xFF)
                .authenticator(auth)
                .attribute(1, imsi)
                .attribute(2, cipher, 0, n);
        int ma = enc.messageAuthenticator();
        int length = enc.finish();
        new RadiusAuthenticator().signAccessRequest(buffer, 0, length, ma, SECRET);
        byte[] reply = exchange(gateway.authPort(), Arrays.copyOf(buffer.byteArray(), length));
        assertThat(reply[0] & 0xFF).isEqualTo(RadiusCode.ACCESS_ACCEPT);
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(reply), 0, reply.length);
        int at = p.findAttribute(18);
        return Long.parseLong(p.buffer()
                .getStringWithoutLengthAscii(at + 2, (p.buffer().getByte(at + 1) & 0xFF) - 2));
    }

    private byte[] warmUp() {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, ++identifier & 0xFF)
                .uint32(40, 1)
                .attribute(44, "warm-up")
                .attribute(1, "nobody")
                .uint32(55, 1_780_000_000L);
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** Sends like a NAS (retransmitting from one source port) and returns the reply to this identifier. */
    private byte[] exchange(int port, byte[] request) throws Exception {
        if (nas == null) {
            nas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
            nas.configureBlocking(false);
        }
        InetSocketAddress target = new InetSocketAddress("127.0.0.1", port);
        ByteBuffer in = ByteBuffer.allocate(4096);
        for (int attempt = 0; attempt < 8; attempt++) {
            nas.send(ByteBuffer.wrap(request), target);
            long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
            while (System.nanoTime() < deadline) {
                in.clear();
                if (nas.receive(in) != null && in.get(1) == request[1]) {
                    return Arrays.copyOf(in.array(), in.position());
                }
                Thread.sleep(2);
            }
        }
        throw new AssertionError("no reply");
    }
}
