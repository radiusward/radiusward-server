/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.client.PacketBuilder;
import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusCode;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
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
 * Proxying over plain TCP and DTLS (ADR 0055): RADIUS server A proxies one realm over TCP and another over DTLS to RADIUS server
 * B, which decides from its users file. The TCP realm is rewritten on the way: Calling-Station-Id removed and an
 * Operator-Name added before B sees it (B's check items require both), Class removed from B's answer.
 */
@Epic("Proxying")
@Feature("Proxying over TCP and DTLS")
@Link(
        name = "ADR 0055",
        url =
                "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0055-proxy-transports-and-rewriting.md")
class ProxyTransportsIT {

    static final String TCP_SECRET = "tcp-home-secret";

    @TempDir
    Path dir;

    private RadiusServer home;
    private RadiusServer proxy;
    private final ProxyIT nas = new ProxyIT();

    @AfterEach
    void stop() throws Exception {
        nas.stop();
        for (RadiusServer g : new RadiusServer[] {proxy, home}) {
            if (g != null) {
                g.close();
            }
        }
    }

    private int start() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        TestPki.Issued client = pki.client("proxy.corp.test");
        Path clientPem = TestPki.write(
                dir.resolve("proxy.pem"), "CERTIFICATE", client.certificate().getEncoded());
        Path clientKey = TestPki.write(
                dir.resolve("proxy.key"),
                "PRIVATE KEY",
                client.keys().getPrivate().getEncoded());
        Path users = Files.writeString(dir.resolve("home-users"), """
                bob@tcp.example     Cleartext-Password := "pw", Operator-Name == "1op.example", Calling-Station-Id !~ "."
                                    Reply-Message = "over tcp", Class = "home-class"
                carol@dtls.example  Cleartext-Password := "pw"
                                    Reply-Message = "over dtls"
                """);
        Config homeSettings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("radius.tcp.enabled", "true"),
                Map.entry("radius.tcp.auth.port", "0"),
                Map.entry("radius.tcp.acct.port", "0"),
                Map.entry("radsec.dtls.enabled", "true"),
                Map.entry("radsec.dtls.port", "0"),
                Map.entry("radsec.certificate", pki.serverPem.toString()),
                Map.entry("radsec.key", pki.serverKey.toString()),
                Map.entry("radsec.ca", pki.caPem.toString()),
                Map.entry("nas.local.address", "127.0.0.1"),
                Map.entry("nas.local.secret", TCP_SECRET),
                Map.entry("nas.local.tcp", "true"),
                Map.entry("nas.local.dtls", "true")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        home = RadiusServer.builder(config("home", 2), NasRegistry.from(homeSettings))
                .auth(auth)
                .handlerFactory(RadiusServer.storeHandler(homeSettings, auth))
                .radsec(RadsecConfig.from(homeSettings, "127.0.0.1"))
                .start();

        Map<String, String> proxySettings = new HashMap<>(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry(
                        "auth.store.local.path",
                        Files.writeString(dir.resolve("none"), "").toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("proxy.enabled", "true"),
                Map.entry("proxy.timeout", "1s"),
                Map.entry("proxy.retries", "2"),
                Map.entry("home.t.address", "127.0.0.1:" + home.tcpPort(true)),
                Map.entry("home.t.transport", "tcp"),
                Map.entry("home.t.secret", TCP_SECRET),
                Map.entry("home.d.address", "127.0.0.1:" + home.dtlsPort()),
                Map.entry("home.d.transport", "dtls"),
                Map.entry("home.d.tls.certificate", clientPem.toString()),
                Map.entry("home.d.tls.key", clientKey.toString()),
                Map.entry("home.d.tls.ca", pki.caPem.toString()),
                Map.entry("home.d.tls.name", "radius.home.test"),
                Map.entry("pool.t.servers", "t"),
                Map.entry("pool.d.servers", "d"),
                Map.entry("realm.t.name", "tcp.example"),
                Map.entry("realm.t.pool", "t"),
                Map.entry("realm.t.pre-proxy.remove", "Calling-Station-Id"),
                Map.entry("realm.t.pre-proxy.add", "Operator-Name = \"1op.example\""),
                Map.entry("realm.t.post-proxy.remove", "Class"),
                Map.entry("realm.d.name", "dtls.example"),
                Map.entry("realm.d.pool", "d")));
        Config config = Config.of(proxySettings);
        proxy = RadiusServer.builder(
                        config("proxy", 1), AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED))
                .auth(auth)
                .handlerFactory(RadiusServer.storeHandler(config, auth))
                .proxy(ProxyConfig.from(config))
                .start();
        return proxy.authPort();
    }

    @Test
    void overTcpRewrittenAndOverDtls() throws Exception {
        int port = start();
        byte[] tcp = nas.pap("bob@tcp.example", "pw", "aa-bb-cc-00-02-01");
        byte[] accept = nas.send(port, tcp, Duration.ofSeconds(5));
        ProxyIT.assertForTheNas(accept, tcp, RadiusCode.ACCESS_ACCEPT);
        assertThat(new String(accept, StandardCharsets.ISO_8859_1)).contains("over tcp");
        assertThat(AuthAgentTest.wrap(accept).findAttribute(25))
                .as("Class removed")
                .isNegative();

        byte[] dtls = nas.pap("carol@dtls.example", "pw", "aa-bb-cc-00-02-02");
        byte[] dtlsAccept = nas.send(port, dtls, Duration.ofSeconds(8));
        ProxyIT.assertForTheNas(dtlsAccept, dtls, RadiusCode.ACCESS_ACCEPT);
        assertThat(new String(dtlsAccept, StandardCharsets.ISO_8859_1)).contains("over dtls");

        byte[] wrong = nas.pap("carol@dtls.example", "nope", "aa-bb-cc-00-02-03");
        ProxyIT.assertForTheNas(nas.send(port, wrong, Duration.ofSeconds(5)), wrong, RadiusCode.ACCESS_REJECT);
        assertThat(proxy.metrics())
                .contains("radiusward_server_proxy_requests_total{server=\"1\",home=\"t\",result=\"accepted\"} 1")
                .contains("radiusward_server_proxy_requests_total{server=\"1\",home=\"d\",result=\"accepted\"} 1")
                .contains("radiusward_server_proxy_requests_total{server=\"1\",home=\"d\",result=\"rejected\"} 1");
    }

    // ---- the connections to a home server, driven directly -----------------------------------------

    private static final Duration MAX = Duration.ofSeconds(10);

    private static byte[] request(int identifier) {
        return PacketBuilder.accessRequest(identifier)
                .attribute(1, "bob@tcp.example")
                .build();
    }

    private static byte[] reply(byte[] request, String message) {
        return PacketBuilder.reply(RadiusCode.ACCESS_ACCEPT, request)
                .secret(TCP_SECRET)
                .attribute(18, message)
                .build();
    }

    /** A request near the largest RADIUS packet, to fill buffers quickly. */
    private static byte[] large(int identifier) {
        PacketBuilder p = PacketBuilder.accessRequest(identifier);
        for (int i = 0; i < 15; i++) {
            p.attribute(18, new byte[253]);
        }
        return p.build();
    }

    private static boolean send(HomeConnection connection, byte[] packet) throws java.io.IOException {
        return connection.send(new UnsafeBuffer(packet), 0, packet.length);
    }

    /** Reads what the home server end of a TCP connection got so far, without waiting. */
    private static void read(SocketChannel home, ByteArrayOutputStream got) throws java.io.IOException {
        ByteBuffer b = ByteBuffer.allocate(64 * 1024);
        int n;
        while ((n = home.read(b)) > 0) {
            got.write(b.array(), 0, n);
            b.clear();
        }
    }

    @Test
    void tcpFramesTheHomeServersPacketsAndRefusesMalformedOnes() throws Exception {
        try (ServerSocketChannel listener = ServerSocketChannel.open();
                HomePeers.Loop loop = new HomePeers.Loop()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            HomeTcpClient tcp = new HomeTcpClient((InetSocketAddress) listener.getLocalAddress());
            byte[] request = request(1);
            assertThat(send(tcp, request)).as("not connected").isFalse();
            tcp.connect(loop.selector);
            assertThat(tcp.open()).isTrue();
            assertThat(send(tcp, request)).as("kept until the connection is up").isTrue();
            try (SocketChannel home = listener.accept()) {
                home.configureBlocking(false);
                ByteArrayOutputStream got = new ByteArrayOutputStream();
                loop.each = () -> read(home, got);
                loop.until(() -> got.size() == request.length, MAX);
                assertThat(got.toByteArray()).isEqualTo(request);

                byte[] first = reply(request, "first");
                byte[] second = reply(request, "second");
                byte[] third = reply(request, "third");
                home.write(ByteBuffer.wrap(concat(first, second, Arrays.copyOf(third, 10))));
                loop.until(() -> loop.packets.size() == 2, MAX);
                home.write(ByteBuffer.wrap(Arrays.copyOfRange(third, 10, third.length)));
                loop.until(() -> loop.packets.size() == 3, MAX);
                assertThat(loop.packets).containsExactly(first, second, third);

                home.write(ByteBuffer.wrap(new byte[] {2, 9, 0, 3}));
                assertThatThrownBy(() -> loop.until(() -> false, MAX))
                        .isInstanceOf(java.io.IOException.class)
                        .hasMessageContaining("malformed RADIUS packet from the home server");
            }
            tcp.close();
            assertThat(tcp.open()).isFalse();
            tcp.close();
            assertThat(send(tcp, request)).isFalse();
        }
    }

    @Test
    void tcpNoticesTheHomeServerClosing() throws Exception {
        try (ServerSocketChannel listener = ServerSocketChannel.open();
                HomePeers.Loop loop = new HomePeers.Loop()) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            HomeTcpClient tcp = new HomeTcpClient((InetSocketAddress) listener.getLocalAddress());
            tcp.connect(loop.selector);
            listener.accept().close();
            assertThatThrownBy(() -> loop.until(() -> false, MAX))
                    .isInstanceOf(java.io.IOException.class)
                    .hasMessage("closed by the home server");
            tcp.connect(loop.selector); // as the proxy does: a new connection for the next request
            try (SocketChannel home = listener.accept()) {
                byte[] request = request(2);
                assertThat(send(tcp, request)).isTrue();
                home.configureBlocking(false);
                ByteArrayOutputStream got = new ByteArrayOutputStream();
                loop.each = () -> read(home, got);
                loop.until(() -> got.size() == request.length, MAX);
                home.write(ByteBuffer.wrap(new byte[] {2, 2, (byte) 0x10, 1})); // longer than any RADIUS packet
                assertThatThrownBy(() -> loop.until(() -> false, MAX))
                        .isInstanceOf(java.io.IOException.class)
                        .hasMessage("malformed RADIUS packet from the home server");
            }
            tcp.close();
        }
    }

    @Test
    void tcpToAHomeServerThatStopsReadingDropsRequestsAndCatchesUpLater() throws Exception {
        try (ServerSocketChannel listener = ServerSocketChannel.open();
                HomePeers.Loop loop = new HomePeers.Loop()) {
            listener.setOption(java.net.StandardSocketOptions.SO_RCVBUF, 4096);
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            HomeTcpClient tcp = new HomeTcpClient((InetSocketAddress) listener.getLocalAddress());
            tcp.connect(loop.selector);
            try (SocketChannel home = listener.accept()) {
                home.configureBlocking(false);
                ByteArrayOutputStream got = new ByteArrayOutputStream();
                byte[] first = request(3);
                assertThat(send(tcp, first)).isTrue();
                loop.each = () -> read(home, got);
                loop.until(() -> got.size() == first.length, MAX);

                byte[] packet = large(4);
                long accepted = first.length;
                int sent = 0;
                while (sent < 100_000 && send(tcp, packet)) { // the home server does not read meanwhile
                    accepted += packet.length;
                    sent++;
                }
                assertThat(sent)
                        .as("the socket and the connection's buffer full: the next request is dropped")
                        .isBetween(1, 99_999);
                long expected = accepted;
                loop.until(() -> got.size() == expected, MAX);
                assertThat(Arrays.copyOfRange(got.toByteArray(), first.length, first.length + packet.length))
                        .as("what waited is written once the home server reads again")
                        .isEqualTo(packet);
            }
            tcp.close();
        }
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    private HomeDtlsClient dtlsClient(TestPki pki, InetSocketAddress home) throws Exception {
        return new HomeDtlsClient(TestPki.clientContext(null, pki.ca, "DTLS"), "radius.home.test", home);
    }

    @Test
    void dtlsWaitsForTheHandshakeAndDiscardsWhatIsNoRadiusPacket() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        try (HomePeers.DtlsHome home = new HomePeers.DtlsHome(HomePeers.serverContext(pki, "DTLS"));
                HomePeers.Loop loop = new HomePeers.Loop()) {
            HomeDtlsClient dtls = dtlsClient(pki, home.address());
            byte[] request = request(5);
            assertThat(send(dtls, request)).as("not connected").isFalse();
            assertThat(dtls.lossy())
                    .as("requests are retransmitted as over UDP")
                    .isTrue();
            dtls.connect(loop.selector);
            assertThat(send(dtls, request))
                    .as("kept until the handshake is done")
                    .isTrue();
            loop.each = home::pump;
            loop.until(() -> home.received.size() == 1, MAX);
            assertThat(home.received.get(0)).isEqualTo(request);
            dtls.tick(System.nanoTime() + HomeDtlsClient.HANDSHAKE_NANOS * 2);
            assertThat(dtls.open())
                    .as("an association is not timed out once established")
                    .isTrue();

            byte[] accept = reply(request, "over dtls");
            home.send(accept);
            loop.until(() -> loop.packets.size() == 1, MAX);
            home.send(new byte[] {2, 5}); // too short for a RADIUS header
            home.send(Arrays.copyOf(accept, 30)); // its length says more than the record holds
            home.sendRaw(new byte[] {1, 2, 3}); // not even DTLS
            byte[] last = reply(request, "last");
            home.send(last);
            loop.until(() -> loop.packets.size() == 2, MAX);
            assertThat(loop.packets).containsExactly(accept, last);

            byte[] after = request(6);
            assertThat(send(dtls, after)).isTrue();
            loop.until(() -> home.received.size() == 2, MAX);
            assertThat(home.received.get(1)).isEqualTo(after);

            dtls.close();
            loop.until(() -> home.closedByPeer, MAX);
            assertThat(dtls.open()).isFalse();
            dtls.close();
        }
    }

    @Test
    void dtlsNoticesTheHomeServerClosing() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        try (HomePeers.DtlsHome home = new HomePeers.DtlsHome(HomePeers.serverContext(pki, "DTLS"));
                HomePeers.Loop loop = new HomePeers.Loop()) {
            HomeDtlsClient dtls = dtlsClient(pki, home.address());
            dtls.connect(loop.selector);
            byte[] request = request(7);
            assertThat(send(dtls, request)).isTrue();
            loop.each = home::pump;
            loop.until(() -> home.received.size() == 1, MAX);
            home.closeNotify();
            assertThatThrownBy(() -> loop.until(() -> false, MAX))
                    .isInstanceOf(java.io.IOException.class)
                    .hasMessage("DTLS closed by the home server");

            home.restart();
            dtls.connect(loop.selector); // as the proxy does: a new association for the next request
            byte[] next = request(8);
            assertThat(send(dtls, next)).isTrue();
            loop.until(() -> home.received.size() == 2, MAX);
            assertThat(home.received.get(1)).isEqualTo(next);
            dtls.close();
        }
    }

    @Test
    void dtlsRetransmitsItsHandshakeWithBackoffAndGivesUp() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        try (HomePeers.DtlsHome silent = new HomePeers.DtlsHome(null);
                HomePeers.Loop loop = new HomePeers.Loop()) {
            HomeDtlsClient dtls = dtlsClient(pki, silent.address());
            dtls.connect(loop.selector);
            long start = System.nanoTime();
            loop.each = silent::pump;
            loop.until(() -> silent.datagrams == 1, MAX);
            assertThat(silent.datagrams).as("the ClientHello").isEqualTo(1);

            long second = HomeDtlsClient.RETRANSMIT_NANOS;
            dtls.tick(start + second / 2);
            dtls.tick(start + second + second / 10);
            loop.until(() -> silent.datagrams >= 2, MAX);
            int afterFirst = silent.datagrams;
            dtls.tick(start + 2 * second + second / 5);
            silent.pump();
            assertThat(silent.datagrams)
                    .as("the interval doubled: not again after another second")
                    .isEqualTo(afterFirst);
            dtls.tick(start + 3 * second + second / 5);
            loop.until(() -> silent.datagrams > afterFirst, MAX);

            int fits = 0;
            byte[] packet = large(8);
            while (fits < 100 && send(dtls, packet)) {
                fits++;
            }
            assertThat(fits)
                    .as("what waits for the handshake is bounded: then requests are dropped")
                    .isBetween(1, 99);

            dtls.tick(start + HomeDtlsClient.HANDSHAKE_NANOS + second);
            assertThat(dtls.open())
                    .as("a handshake not done in time is given up")
                    .isFalse();
            dtls.tick(start + HomeDtlsClient.HANDSHAKE_NANOS + 2 * second);
        }
    }

    private ServerConfig config(String name, int id) {
        ServerConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        return new ServerConfig(
                id,
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
                new File(dir.toFile(), "aeron-" + name).getPath(),
                c.dictionaryDir(),
                c.debugResponseDelay());
    }
}
