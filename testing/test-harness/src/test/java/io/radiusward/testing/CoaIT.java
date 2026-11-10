/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import io.radiusward.common.management.Health;
import io.radiusward.common.management.ManagementServer;
import io.radiusward.gateway.AuthConfig;
import io.radiusward.gateway.CoaConfig;
import io.radiusward.gateway.DtlsClient;
import io.radiusward.gateway.DynamicAuthorization;
import io.radiusward.gateway.Gateway;
import io.radiusward.gateway.RadsecClient;
import io.radiusward.gateway.RadsecConfig;
import io.radiusward.gateway.TestPki;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.tools.admin.AdminMain;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * CoA and Disconnect (RFC 5176, ADR 0036) with 3 members: sessions found in the replicated state by user or by
 * Acct-Session-Id, requests to a fake NAS over UDP — through the gateway's HTTP API and {@code admin} — and to a NAS
 * on its RadSec connection.
 */
class CoaIT {

    static final String TOKEN = "coa-token-0123456789";
    static final byte[] UDP_SECRET = LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private LocalCluster cluster;
    private ManagementServer management;
    private DatagramChannel fakeNas;
    private final AtomicBoolean answering = new AtomicBoolean(true);
    private final List<byte[]> requests = new CopyOnWriteArrayList<>();
    private final LocalClusterIT nas = new LocalClusterIT();

    @AfterEach
    void close() throws Exception {
        answering.set(false);
        nas.close();
        if (management != null) {
            management.close();
        }
        if (fakeNas != null) {
            fakeNas.close();
        }
        if (cluster != null) {
            cluster.close();
        }
    }

    private Gateway start(RadsecConfig radsec) throws Exception {
        return start(radsec, Map.of());
    }

    /** @param proxy {@code proxy.*}, {@code home.*}, ... settings: proxying, with authentication from an empty store */
    private Gateway start(RadsecConfig radsec, Map<String, String> proxy) throws Exception {
        fakeNas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        int nasPort = ((InetSocketAddress) fakeNas.getLocalAddress()).getPort();
        CompletableFuture.runAsync(this::answer);
        cluster = LocalCluster.start(
                dir.resolve("cluster").toFile(),
                3,
                0,
                LocalCluster.freePortBase(3),
                new int[0],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)));
        CoaConfig coa = CoaConfig.from(Config.of(Map.of(
                "coa.enabled",
                "true",
                "coa.timeout",
                "300ms",
                "coa.retries",
                "1",
                "coa.api.token",
                TOKEN,
                "nas." + LocalCluster.NAS_NAME + ".coa.port",
                Integer.toString(nasPort))));
        Gateway gateway;
        if (proxy.isEmpty()) {
            gateway = cluster.startGateway(
                    1, LocalCluster.freePort(), LocalCluster.registry(), AuthConfig.DISABLED, d -> null, radsec, coa);
        } else {
            Map<String, String> settings = new java.util.HashMap<>(proxy);
            settings.put("auth.stores", "local");
            settings.put("auth.store.local.type", "file");
            settings.put(
                    "auth.store.local.path",
                    java.nio.file.Files.writeString(dir.resolve("users"), "").toString());
            settings.put("auth.plugins.dir", dir.resolve("plugins").toString());
            Config config = Config.of(settings);
            AuthConfig auth = new AuthConfig(true, 0, 1, 64, 1024, Duration.ofSeconds(10));
            gateway = cluster.startGateway(
                    1,
                    LocalCluster.freePort(),
                    LocalCluster.registry(),
                    auth,
                    Gateway.storeHandler(config, auth),
                    radsec,
                    coa,
                    io.radiusward.gateway.ProxyConfig.from(config));
        }
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        nas.exchange(gateway.radiusPort(), SessionIdentityIT.start(99, "warm-up", "nobody", "aa-bb-cc-00-00-99"));
        try (io.radiusward.tools.admin.AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(20),
                    "state version 7",
                    () -> admin.state().activeVersion() >= 7);
        }
        management = ManagementServer.start(
                        "127.0.0.1", 0, () -> Health.up("ok"), () -> Health.up("ok"), () -> "{}", gateway::metrics)
                .handle("/coa/", gateway.coaApi());
        return gateway;
    }

    /** The fake NAS: acknowledges every Disconnect- and CoA-Request, signed with the NAS's secret. */
    private void answer() {
        ByteBuffer in = ByteBuffer.allocate(4096);
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        while (answering.get()) {
            try {
                in.clear();
                InetSocketAddress from = (InetSocketAddress) fakeNas.receive(in);
                if (from == null) {
                    continue;
                }
                byte[] request = Arrays.copyOf(in.array(), in.position());
                RadiusPacket p = new RadiusPacket();
                p.wrap(new UnsafeBuffer(request), 0, request.length);
                if (!authenticator.verifyAccountingRequest(p, UDP_SECRET)) {
                    continue;
                }
                requests.add(request);
                fakeNas.send(ByteBuffer.wrap(ack(request, UDP_SECRET)), from);
            } catch (Exception e) {
                return; // closed
            }
        }
    }

    static byte[] ack(byte[] request, byte[] secret) {
        UnsafeBuffer out = new UnsafeBuffer(new byte[20]);
        out.putByte(0, (byte) (request[0] + 1));
        out.putByte(1, request[1]);
        out.putShort(2, (short) 20, java.nio.ByteOrder.BIG_ENDIAN);
        new RadiusAuthenticator().signResponse(out, 0, 20, -1, new UnsafeBuffer(request), 4, secret);
        return out.byteArray();
    }

    private HttpResponse<String> post(String path, String body, String token) throws Exception {
        return HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + management.port() + path))
                                .header("Authorization", "Bearer " + token)
                                .POST(HttpRequest.BodyPublishers.ofString(body))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
    }

    static String attribute(byte[] packet, int type) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(packet), 0, packet.length);
        int at = p.findAttribute(type);
        return at < 0 ? null : new String(packet, at + 2, (packet[at + 1] & 0xFF) - 2, StandardCharsets.ISO_8859_1);
    }

    @Test
    void disconnectAndChangeThroughTheApiAndAdmin() throws Exception {
        Gateway gateway = start(RadsecConfig.DISABLED);
        int port = gateway.radiusPort();
        nas.exchange(port, SessionIdentityIT.start(1, "s-alice-1", "alice", "aa-bb-cc-00-00-01"));
        nas.exchange(port, SessionIdentityIT.start(2, "s-alice-2", "alice", "aa-bb-cc-00-00-02"));
        nas.exchange(port, SessionIdentityIT.start(3, "s-bob", "bob", "aa-bb-cc-00-00-03"));

        assertThat(post("/coa/disconnect?user=alice", "", "wrong-token").statusCode())
                .isEqualTo(401);

        HttpResponse<String> disconnect = post("/coa/disconnect?user=alice", "", TOKEN);
        assertThat(disconnect.statusCode()).isEqualTo(200);
        assertThat(disconnect.body())
                .contains("\"session\":\"s-alice-1\"")
                .contains("\"session\":\"s-alice-2\"")
                .doesNotContain("s-bob")
                .contains("\"result\":\"ack\"")
                .doesNotContain("timeout");
        assertThat(requests).hasSize(2).allSatisfy(r -> {
            assertThat(r[0]).isEqualTo((byte) 40);
            assertThat(attribute(r, 1)).isEqualTo("alice");
            assertThat(attribute(r, 4))
                    .as("NAS-IP-Address added from the entry")
                    .isNotNull();
            assertThat(attribute(r, 80)).as("Message-Authenticator").isNotNull();
        });

        requests.clear();
        HttpResponse<String> change = post("/coa/update?user=alice", "Session-Timeout = 600", TOKEN);
        assertThat(change.body()).contains("\"result\":\"ack\"");
        assertThat(requests).hasSize(2).allSatisfy(r -> {
            assertThat(r[0]).isEqualTo((byte) 43);
            assertThat(attribute(r, 27)).as("Session-Timeout").isNotNull();
        });

        requests.clear();
        assertThat(post("/coa/disconnect?nas=local&session=s-bob", "", TOKEN).body())
                .contains("\"user\":\"bob\"")
                .contains("\"result\":\"ack\"");
        assertThat(post("/coa/disconnect?user=nobody-at-all", "", TOKEN).body()).isEqualTo("{\"sessions\":[]}");
        assertThat(post("/coa/update?user=alice", "No-Such-Attribute = 1", TOKEN)
                        .statusCode())
                .isEqualTo(400);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int exit = AdminMain.run(
                new String[] {
                    "disconnect",
                    "--gateway",
                    "http://127.0.0.1:" + management.port(),
                    "--token",
                    TOKEN,
                    "--user",
                    "bob"
                },
                new PrintStream(out),
                new PrintStream(new ByteArrayOutputStream()));
        assertThat(exit).as(out.toString()).isZero();
        assertThat(out.toString()).contains("\"result\":\"ack\"");
        assertThat(gateway.metrics()).contains("radiusward_gateway_coa_requests_total{gateway=\"1\",result=\"ack\"} 6");
    }

    @Test
    void aNasOnRadsecGetsItOnItsConnection() throws Exception {
        TestPki pki = new TestPki(dir, "coa");
        Gateway gateway = start(RadsecConfig.from(
                Config.of(Map.of(
                        "radsec.enabled",
                        "true",
                        "radsec.port",
                        "0",
                        "radsec.certificate",
                        pki.serverPem.toString(),
                        "radsec.key",
                        pki.serverKey.toString(),
                        "radsec.ca",
                        pki.caPem.toString(),
                        "nas." + LocalCluster.NAS_NAME + ".radsec",
                        "true")),
                "127.0.0.1"));
        byte[] radsec = "radsec".getBytes(StandardCharsets.US_ASCII);
        try (RadsecClient client =
                new RadsecClient(gateway.radsecPort(), TestPki.clientContext(pki.client("nas"), pki.ca), "TLSv1.3")) {
            byte[] start = accounting(5, "s-carol", "carol", radsec);
            client.send(start);
            assertThat(client.receive()[0]).isEqualTo((byte) RadiusCode.ACCOUNTING_RESPONSE);

            CompletableFuture<HttpResponse<String>> call = CompletableFuture.supplyAsync(() -> {
                try {
                    return post("/coa/disconnect?user=carol", "", TOKEN);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            byte[] request = client.receive();
            assertThat(request[0])
                    .as("Disconnect-Request on the RadSec connection")
                    .isEqualTo((byte) 40);
            RadiusPacket p = new RadiusPacket();
            p.wrap(new UnsafeBuffer(request), 0, request.length);
            assertThat(new RadiusAuthenticator().verifyAccountingRequest(p, radsec))
                    .isTrue();
            client.send(ack(request, radsec));
            assertThat(call.join().body()).contains("\"session\":\"s-carol\"").contains("\"result\":\"ack\"");
        }
        assertThat(requests).as("nothing over UDP").isEmpty();
    }

    @Test
    void aNasOnDtlsGetsItOnItsAssociation() throws Exception {
        TestPki pki = new TestPki(dir, "coa-dtls");
        Gateway gateway = start(RadsecConfig.from(
                Config.of(Map.of(
                        "radsec.dtls.enabled",
                        "true",
                        "radsec.dtls.port",
                        "0",
                        "radsec.certificate",
                        pki.serverPem.toString(),
                        "radsec.key",
                        pki.serverKey.toString(),
                        "radsec.ca",
                        pki.caPem.toString(),
                        "nas." + LocalCluster.NAS_NAME + ".dtls",
                        "true")),
                "127.0.0.1"));
        byte[] dtls = "radius/dtls".getBytes(StandardCharsets.US_ASCII);
        try (DtlsClient client =
                new DtlsClient(gateway.dtlsPort(), TestPki.clientContext(pki.client("nas"), pki.ca, "DTLS"))) {
            byte[] start = accounting(6, "s-dave", "dave", dtls);
            client.send(start);
            assertThat(client.receive()[0]).isEqualTo((byte) RadiusCode.ACCOUNTING_RESPONSE);

            CompletableFuture<HttpResponse<String>> call = CompletableFuture.supplyAsync(() -> {
                try {
                    return post("/coa/disconnect?user=dave", "", TOKEN);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            byte[] request = client.receive();
            assertThat(request[0])
                    .as("Disconnect-Request on the DTLS association")
                    .isEqualTo((byte) 40);
            RadiusPacket p = new RadiusPacket();
            p.wrap(new UnsafeBuffer(request), 0, request.length);
            assertThat(new RadiusAuthenticator().verifyAccountingRequest(p, dtls))
                    .as("signed with radius/dtls")
                    .isTrue();
            client.send(ack(request, dtls));
            assertThat(call.join().body()).contains("\"session\":\"s-dave\"").contains("\"result\":\"ack\"");
        }
        assertThat(requests).as("nothing over UDP").isEmpty();
    }

    /**
     * A home server of a proxied realm disconnects its user through the relay (ADR 0043): the request reaches the NAS
     * signed for it, without the home server's Proxy-State; the ACK comes back with it, signed with the home secret.
     * A retransmission gets the same answer without a second request; an unknown session a NAK with Error-Cause 503;
     * a wrong secret nothing.
     */
    @Test
    void aHomeServerDisconnectsItsUserThroughTheRelay() throws Exception {
        byte[] homeSecret = "home-secret".getBytes(StandardCharsets.US_ASCII);
        Gateway gateway = start(
                RadsecConfig.DISABLED,
                Map.of(
                        "proxy.enabled", "true",
                        "proxy.coa.port", "0",
                        "home.partner.address", "127.0.0.1:9",
                        "home.partner.secret", "home-secret",
                        "home.partner.coa", "true",
                        "pool.partner.servers", "partner",
                        "realm.partner.name", "partner.example",
                        "realm.partner.pool", "partner"));
        assertThat(gateway.coaRelayPort()).isPositive();
        nas.exchange(gateway.radiusPort(), accounting(7, "s-erin", "erin@partner.example", UDP_SECRET));

        try (DatagramChannel home = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0))) {
            home.socket().setSoTimeout(5_000);
            InetSocketAddress relay = new InetSocketAddress("127.0.0.1", gateway.coaRelayPort());
            byte[] request = homeRequest(
                    11, DynamicAuthorization.DISCONNECT_REQUEST, "erin@partner.example", "s-erin", homeSecret);
            home.send(ByteBuffer.wrap(request), relay);
            byte[] answer = receive(home);
            assertThat(answer[0]).as("Disconnect-ACK").isEqualTo((byte) DynamicAuthorization.DISCONNECT_ACK);
            RadiusPacket a = new RadiusPacket();
            a.wrap(new UnsafeBuffer(answer), 0, answer.length);
            assertThat(new RadiusAuthenticator().verifyResponse(a, new UnsafeBuffer(request), 4, homeSecret))
                    .isTrue();
            assertThat(attribute(answer, 33))
                    .as("the home server's Proxy-State")
                    .isEqualTo("home-state");
            assertThat(requests).hasSize(1);
            byte[] atNas = requests.get(0);
            assertThat(attribute(atNas, 1)).isEqualTo("erin@partner.example");
            assertThat(attribute(atNas, 44)).isEqualTo("s-erin");
            assertThat(attribute(atNas, 33))
                    .as("no Proxy-State of the home server at the NAS")
                    .isNull();

            home.send(ByteBuffer.wrap(request), relay); // retransmitted
            assertThat(receive(home)).isEqualTo(answer);
            assertThat(requests).as("not sent to the NAS again").hasSize(1);

            byte[] unknown =
                    homeRequest(12, DynamicAuthorization.COA_REQUEST, "nobody@partner.example", "s-none", homeSecret);
            home.send(ByteBuffer.wrap(unknown), relay);
            byte[] nak = receive(home);
            assertThat(nak[0]).isEqualTo((byte) DynamicAuthorization.COA_NAK);
            RadiusPacket n = new RadiusPacket();
            n.wrap(new UnsafeBuffer(nak), 0, nak.length);
            int cause = n.findAttribute(101);
            assertThat(new UnsafeBuffer(nak).getInt(cause + 2, java.nio.ByteOrder.BIG_ENDIAN))
                    .as("Session Context Not Found")
                    .isEqualTo(503);

            home.send(
                    ByteBuffer.wrap(homeRequest(
                            13,
                            DynamicAuthorization.DISCONNECT_REQUEST,
                            "erin@partner.example",
                            "s-erin",
                            "wrong".getBytes(StandardCharsets.US_ASCII))),
                    relay);
            LocalCluster.await(
                    Duration.ofSeconds(5),
                    "the forged request counted",
                    () -> gateway.metrics()
                            .contains(
                                    "radiusward_gateway_coa_relay_total{gateway=\"1\",result=\"bad_authenticator\"} 1"));
        }
        assertThat(gateway.metrics())
                .contains("radiusward_gateway_coa_relay_total{gateway=\"1\",result=\"ack\"} 1")
                .contains("radiusward_gateway_coa_relay_total{gateway=\"1\",result=\"duplicate\"} 1")
                .contains("radiusward_gateway_coa_relay_total{gateway=\"1\",result=\"no_session\"} 1");
    }

    /** A CoA or Disconnect-Request from a home server: user, session, its Proxy-State, Message-Authenticator. */
    static byte[] homeRequest(int id, int code, String user, String sessionId, byte[] secret) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(code, id).attribute(1, user).attribute(44, sessionId).attribute(33, "home-state");
        int ma = enc.messageAuthenticator();
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, ma, secret);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    private static byte[] receive(DatagramChannel channel) throws Exception {
        ByteBuffer in = ByteBuffer.allocate(4096);
        long deadline = System.nanoTime() + 5_000_000_000L;
        channel.configureBlocking(false);
        while (System.nanoTime() < deadline) {
            if (channel.receive(in) != null) {
                return Arrays.copyOf(in.array(), in.position());
            }
            Thread.sleep(10);
        }
        throw new AssertionError("no answer from the relay");
    }

    static byte[] accounting(int id, String sessionId, String user, byte[] secret) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id)
                .uint32(40, 1)
                .attribute(44, sessionId)
                .attribute(1, user)
                .uint32(55, 1_780_000_000L);
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, secret);
        return Arrays.copyOf(buffer.byteArray(), length);
    }
}
