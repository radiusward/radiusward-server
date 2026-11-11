/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * RADIUS over plain TCP (RFC 6613, ADR 0045) through the real gateway, without any certificate: Access-Requests and
 * Status-Server on the authentication port with the NAS entry's own secret, an Accounting-Request there discarded, a
 * NAS entry that does not allow TCP refused at once, a malformed length closing the connection. Accounting over TCP
 * with a cluster: {@code RadsecAccountingIT}.
 */
@Epic("Transports")
@Feature("RADIUS over TCP")
@Link(
        name = "ADR 0045",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0045-radius-over-tcp.md")
class RadiusTcpIT {

    @TempDir
    Path dir;

    private Gateway gateway;

    @AfterEach
    void stop() {
        if (gateway != null) {
            gateway.close();
        }
    }

    /** A blocking RADIUS/TCP client: packets written and read by their length field. */
    static final class TcpClient implements AutoCloseable {
        final Socket socket;
        final DataInputStream in;
        final OutputStream out;

        TcpClient(int port) throws IOException {
            socket = new Socket("127.0.0.1", port);
            socket.setSoTimeout(3_000);
            in = new DataInputStream(socket.getInputStream());
            out = socket.getOutputStream();
        }

        void send(byte[] packet) throws IOException {
            out.write(packet);
            out.flush();
        }

        /** The next packet, {@code null} when the server closed or nothing came within the timeout. */
        byte[] receive() throws IOException {
            byte[] header = new byte[4];
            try {
                in.readFully(header);
            } catch (EOFException | SocketTimeoutException e) {
                return null;
            }
            int length = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
            byte[] packet = Arrays.copyOf(header, length);
            in.readFully(packet, 4, length - 4);
            return packet;
        }

        boolean closedByServer() throws IOException {
            try {
                return in.read() < 0;
            } catch (SocketTimeoutException e) {
                return false;
            } catch (IOException e) {
                return true;
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    private void start(boolean allowTcp) throws Exception {
        Path users = Files.writeString(dir.resolve("users"), "nemo    Cleartext-Password := \"arctangent\"\n");
        Map<String, String> settings = new HashMap<>(Map.of(
                "auth.stores", "local",
                "auth.store.local.type", "file",
                "auth.store.local.path", users.toString(),
                "auth.plugins.dir", dir.resolve("no-plugins").toString(),
                "radius.tcp.enabled", "true",
                "radius.tcp.auth.port", "0",
                "radius.tcp.acct.port", "0",
                "nas.local.tcp", Boolean.toString(allowTcp),
                "nas.other.tcp", "true"));
        Config config = Config.of(settings);
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        gateway = Gateway.launchWith(
                new GatewayConfig(
                        c.gatewayId(),
                        c.listenHost(),
                        0,
                        c.socketReceiveBuffer(),
                        c.clusterMembers(),
                        c.clusterBasePort(),
                        c.egressHost(),
                        c.profile(),
                        c.pendingCapacity(),
                        c.pendingTimeout(),
                        c.resubmitAfter(),
                        c.responseCacheTtl(),
                        c.dedicatedThreads(),
                        c.idleStrategy(),
                        new File(dir.toFile(), "aeron").getPath(),
                        c.dictionaryDir(),
                        c.debugResponseDelay()),
                NasRegistry.of(java.util.List.of(
                        AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED)
                                .clients()
                                .iterator()
                                .next(),
                        new NasClient(
                                "other",
                                2002,
                                0x0A000001,
                                32,
                                "other".getBytes(),
                                "default",
                                NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                                new NasClient.Identity[0],
                                0,
                                NasClient.MessageAuthenticatorPolicy.REQUIRED))),
                auth,
                Gateway.storeHandler(config, auth),
                RadsecConfig.from(config, "127.0.0.1"));
    }

    @Test
    void accessRequestsAndStatusServerWithTheNasSecret() throws Exception {
        start(true);
        assertThat(gateway.radsecPort()).as("no TLS listener").isEqualTo(-1);
        try (TcpClient client = new TcpClient(gateway.tcpPort(true))) {
            byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false);
            client.send(good);
            AuthAgentTest.assertSignedReplyTo(client.receive(), good, RadiusCode.ACCESS_ACCEPT);
            byte[] wrong = AuthAgentTest.accessRequest(2, "wrong", true, false);
            client.send(wrong);
            AuthAgentTest.assertSignedReplyTo(client.receive(), wrong, RadiusCode.ACCESS_REJECT);
            client.send(AuthAgentTest.statusServer(3, true, AuthAgentTest.SECRET));
            assertThat(client.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);

            client.send(accounting(4)); // the accounting port's kind: discarded here
            assertThat(client.receive()).isNull();
        }
        RadsecAgent agent = gateway.radsecAgent();
        assertThat(agent.getTcp(RadsecAgent.Counter.REPLIES)).isEqualTo(3);
        assertThat(agent.getTcp(RadsecAgent.Counter.NOT_HANDLED)).isEqualTo(1);
        assertThat(gateway.metrics())
                .contains("radiusward_gateway_tcp_total{gateway=\"1\",result=\"connections_accepted\"} 1");
    }

    @Test
    void aNasEntryWithoutTcpIsRefusedAndMalformedLengthsClose() throws Exception {
        start(false);
        try (TcpClient refused = new TcpClient(gateway.tcpPort(true))) {
            assertThat(refused.closedByServer()).isTrue();
        }
        assertThat(gateway.radsecAgent().getTcp(RadsecAgent.Counter.NAS_REFUSED))
                .isEqualTo(1);
        gateway.close();
        gateway = null;

        start(true);
        try (TcpClient client = new TcpClient(gateway.tcpPort(false))) {
            client.send(new byte[] {4, 1, 0, 3});
            assertThat(client.closedByServer()).isTrue();
        }
        assertThat(gateway.radsecAgent().getTcp(RadsecAgent.Counter.MALFORMED)).isEqualTo(1);
    }

    static byte[] accounting(int id) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id).uint32(40, 1).attribute(44, "tcp-1");
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, AuthAgentTest.SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }
}
