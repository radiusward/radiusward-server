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
import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.testing.packets.TestPacket;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proxying over RadSec (ADR 0037, milestone 4): RADIUS server A proxies a realm to RADIUS server B, its home server, over TLS
 * with a client certificate; B decides from its own store. The NAS talks UDP to A and gets B's answer, signed for it.
 * A home server whose certificate does not carry the expected name gets nothing.
 */
@Epic("Proxying")
@Feature("Proxying over RadSec")
@Link(name = "ADR 0037", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0037-proxying.md")
class ProxyRadsecIT {

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

    private int start(String expectedName) throws Exception {
        TestPki pki = new TestPki(dir, "home");
        TestPki.Issued client = pki.client("proxy.corp.test");
        Path clientPem = TestPki.write(
                dir.resolve("proxy.pem"), "CERTIFICATE", client.certificate().getEncoded());
        Path clientKey = TestPki.write(
                dir.resolve("proxy.key"),
                "PRIVATE KEY",
                client.keys().getPrivate().getEncoded());
        Path users = Files.writeString(dir.resolve("home-users"), """
                alice@partner.example  Cleartext-Password := "home-pw"
                                       Reply-Message = "decided at home"
                """);
        Config homeSettings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("radsec.enabled", "true"),
                Map.entry("radsec.port", "0"),
                Map.entry("radsec.certificate", pki.serverPem.toString()),
                Map.entry("radsec.key", pki.serverKey.toString()),
                Map.entry("radsec.ca", pki.caPem.toString()),
                Map.entry("nas.local.radsec", "true"),
                Map.entry("nas.local.radsec.identity", "proxy.corp.test")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        home = RadiusServer.builder(
                        config("home", 2), AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED))
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
                Map.entry("proxy.timeout", "500ms"),
                Map.entry("proxy.retries", "1"),
                Map.entry("home.b.address", "127.0.0.1:" + home.radsecPort()),
                Map.entry("home.b.transport", "tls"),
                Map.entry("home.b.tls.certificate", clientPem.toString()),
                Map.entry("home.b.tls.key", clientKey.toString()),
                Map.entry("home.b.tls.ca", pki.caPem.toString()),
                Map.entry("home.b.tls.name", expectedName),
                Map.entry("pool.partner.servers", "b"),
                Map.entry("realm.partner.name", "partner.example"),
                Map.entry("realm.partner.pool", "partner")));
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
    void theHomeServerDecidesOverTls() throws Exception {
        int port = start("radius.home.test");
        byte[] good = nas.pap("alice@partner.example", "home-pw", "aa-bb-cc-00-01-01");
        byte[] accept = nas.send(port, good, Duration.ofSeconds(5));
        ProxyIT.assertForTheNas(accept, good, RadiusCode.ACCESS_ACCEPT);
        assertThat(new String(accept, StandardCharsets.ISO_8859_1)).contains("decided at home");

        byte[] wrong = nas.pap("alice@partner.example", "wrong", "aa-bb-cc-00-01-02");
        ProxyIT.assertForTheNas(nas.send(port, wrong, Duration.ofSeconds(5)), wrong, RadiusCode.ACCESS_REJECT);
        assertThat(proxy.metrics())
                .contains("radiusward_server_proxy_requests_total{server=\"1\",home=\"b\",result=\"accepted\"} 1")
                .contains("radiusward_server_proxy_requests_total{server=\"1\",home=\"b\",result=\"rejected\"} 1");
    }

    @Test
    void aHomeServerWithAnotherNameGetsNothing() throws Exception {
        int port = start("someone-else.test");
        byte[] request = nas.pap("alice@partner.example", "home-pw", "aa-bb-cc-00-01-03");
        assertThat(nas.send(port, request, Duration.ofSeconds(2))).isNull();
        assertThat(home.radsecAgent().get(RadsecAgent.Counter.REQUESTS)).isZero();
    }

    // ---- the RadSec connection to a home server, driven directly ------------------------------------

    private static final Duration MAX = Duration.ofSeconds(10);

    private static byte[] request(int identifier) {
        return TestPacket.accessRequest(identifier)
                .attribute(1, "alice@partner.example")
                .build();
    }

    private static byte[] reply(byte[] request, String message) {
        return TestPacket.reply(RadiusCode.ACCESS_ACCEPT, request)
                .secret("radsec")
                .attribute(18, message)
                .build();
    }

    private static boolean send(TlsClient tls, byte[] packet) throws IOException {
        return tls.send(new UnsafeBuffer(packet), 0, packet.length);
    }

    /** One RADIUS packet from a RadSec stream. */
    private static byte[] readPacket(InputStream in) throws IOException {
        byte[] header = in.readNBytes(4);
        int length = (header[2] & 0xFF) << 8 | (header[3] & 0xFF);
        byte[] packet = Arrays.copyOf(header, length);
        System.arraycopy(in.readNBytes(length - 4), 0, packet, 4, length - 4);
        return packet;
    }

    /** A TLS home server on another thread: accepts one connection, then does what {@code script} says. */
    private interface Script {
        void run(SSLSocket socket) throws Exception;
    }

    private SSLServerSocket listener;
    private Thread homeThread;
    private final AtomicReference<Throwable> homeFailure = new AtomicReference<>();

    private InetSocketAddress tlsHome(TestPki pki, Script script) throws Exception {
        listener = (SSLServerSocket) HomePeers.serverContext(pki, "TLS")
                .getServerSocketFactory()
                .createServerSocket(0, 5, InetAddress.getLoopbackAddress());
        listener.setReceiveBufferSize(4096);
        homeThread = Thread.ofPlatform().daemon().start(() -> {
            try (SSLSocket socket = (SSLSocket) listener.accept()) {
                socket.startHandshake();
                script.run(socket);
            } catch (Throwable e) {
                homeFailure.set(e);
            }
        });
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), listener.getLocalPort());
    }

    @AfterEach
    void stopTlsHome() throws Exception {
        if (listener != null) {
            listener.close();
            homeThread.join(10_000);
        }
    }

    private TlsClient tlsClient(TestPki pki, InetSocketAddress home) throws Exception {
        return new TlsClient(TestPki.clientContext(null, pki.ca), "radius.home.test", home);
    }

    @Test
    void radsecWaitsForTheHandshakeAndFramesTheHomeServersPackets() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        byte[] first = request(1);
        byte[] second = request(2);
        byte[][] replies = {reply(first, "one"), reply(first, "two"), reply(first, "three")};
        CountDownLatch rest = new CountDownLatch(1);
        List<byte[]> got = new java.util.concurrent.CopyOnWriteArrayList<>();
        InetSocketAddress home = tlsHome(pki, socket -> {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            got.add(readPacket(in));
            out.write(replies[0]);
            out.write(replies[1]);
            out.write(replies[2], 0, 10); // a packet split over two records
            out.flush();
            rest.await();
            out.write(replies[2], 10, replies[2].length - 10);
            out.flush();
            got.add(readPacket(in));
            out.write(new byte[] {2, 9, 0, 3});
            out.flush();
            try {
                in.read(); // until the proxy closes
            } catch (IOException e) {
                // it closed without close_notify
            }
        });
        try (HomePeers.Loop loop = new HomePeers.Loop()) {
            TlsClient tls = tlsClient(pki, home);
            assertThat(send(tls, first)).as("not connected").isFalse();
            tls.connect(loop.selector);
            assertThat(send(tls, first)).as("kept until the handshake is done").isTrue();
            assertThat(tls.established()).isFalse();
            loop.until(() -> loop.packets.size() == 2, MAX);
            assertThat(tls.established()).isTrue();
            rest.countDown();
            loop.until(() -> loop.packets.size() == 3, MAX);
            assertThat(loop.packets).containsExactly(replies);
            assertThat(send(tls, second)).isTrue();
            assertThatThrownBy(() -> loop.until(() -> false, MAX))
                    .isInstanceOf(IOException.class)
                    .hasMessage("malformed RADIUS packet from the home server");
            assertThat(got).containsExactly(first, second);
            tls.close();
            assertThat(tls.open()).isFalse();
            tls.close();
        }
        homeThread.join(10_000);
        assertThat(homeFailure.get()).isNull();
    }

    private static int available(java.net.Socket socket) {
        try {
            return socket.getInputStream().available();
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    @Test
    void radsecNoticesTheHomeServerClosing() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        InetSocketAddress home = tlsHome(pki, socket -> socket.close()); // close_notify after the handshake
        try (HomePeers.Loop loop = new HomePeers.Loop()) {
            TlsClient tls = tlsClient(pki, home);
            tls.connect(loop.selector);
            assertThatThrownBy(() -> loop.until(() -> false, MAX))
                    .isInstanceOf(IOException.class)
                    .hasMessage("TLS closed by the home server");
            assertThatThrownBy(() -> send(tls, request(9)))
                    .as("nothing more goes out on a closed session")
                    .isInstanceOf(javax.net.ssl.SSLException.class)
                    .hasMessage("TLS closed");
            tls.close();
        }

        try (ServerSocket plain = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
                HomePeers.Loop loop = new HomePeers.Loop()) {
            TlsClient tls =
                    tlsClient(pki, new InetSocketAddress(InetAddress.getLoopbackAddress(), plain.getLocalPort()));
            tls.connect(loop.selector);
            try (java.net.Socket socket = plain.accept()) {
                loop.until(() -> available(socket) > 0, MAX); // the ClientHello came
                socket.shutdownOutput(); // the connection closed before any TLS from the home server
                assertThatThrownBy(() -> loop.until(() -> false, MAX))
                        .isInstanceOf(IOException.class)
                        .hasMessage("closed by the home server");
            }
            tls.close();
        }
    }

    @Test
    void radsecToAHomeServerByAddressNeedsItInTheCertificate() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        InetSocketAddress home = tlsHome(pki, socket -> {});
        try (HomePeers.Loop loop = new HomePeers.Loop()) {
            TlsClient tls = new TlsClient(TestPki.clientContext(null, pki.ca), "127.0.0.1", home);
            tls.connect(loop.selector);
            assertThatThrownBy(() -> loop.until(() -> false, MAX))
                    .as("no SNI for an address, and the certificate names no address")
                    .isInstanceOf(javax.net.ssl.SSLException.class);
            tls.close();
        }
    }

    @Test
    void radsecToAHomeServerThatDoesNotReadGivesUp() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        CountDownLatch done = new CountDownLatch(1);
        InetSocketAddress home = tlsHome(pki, socket -> done.await());
        try (HomePeers.Loop loop = new HomePeers.Loop()) {
            TlsClient tls = tlsClient(pki, home);
            tls.connect(loop.selector);
            byte[] early = TestPacket.accessRequest(4)
                    .attribute(18, new byte[253])
                    .attribute(18, new byte[253])
                    .build();
            int waiting = 0;
            while (waiting < 1_000 && send(tls, early)) {
                waiting++;
            }
            assertThat(waiting)
                    .as("what waits for the handshake is bounded: then requests are dropped")
                    .isBetween(1, 999);
            loop.until(tls::established, MAX);
            byte[] packet = TestPacket.accessRequest(3)
                    .attribute(18, new byte[253])
                    .attribute(18, new byte[253])
                    .attribute(18, new byte[253])
                    .attribute(18, new byte[253])
                    .build();
            int sent = 0;
            IOException stopped = null;
            try {
                while (sent < 1_000_000) {
                    assertThat(send(tls, packet)).isTrue();
                    sent++;
                }
            } catch (IOException e) {
                stopped = e;
            }
            assertThat(stopped)
                    .as("over a megabyte waiting: the connection is given up")
                    .isNotNull()
                    .hasMessage("home server does not read");
            assertThat(sent).isPositive();
            tls.close();
        } finally {
            done.countDown();
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
