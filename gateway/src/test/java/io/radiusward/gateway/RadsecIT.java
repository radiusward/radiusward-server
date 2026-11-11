/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * RadSec (RFC 6614) through the real gateway: Access-Requests and Status-Server over TLS 1.3 and 1.2, many requests in
 * flight on one connection, client certificates required and checked, NAS entries that do not allow RadSec,
 * malformed packets closing the connection. Accounting over RadSec with a cluster: {@code RadsecAccountingIT}.
 */
@Epic("Transports")
@Feature("RadSec")
@Link(name = "ADR 0034", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0034-radsec.md")
class RadsecIT {

    static final byte[] RADSEC = "radsec".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    static Path dir;

    static TestPki pki;
    static TestPki stranger;

    private Gateway gateway;

    @BeforeAll
    static void certificates() throws Exception {
        pki = new TestPki(dir, "radsec");
        stranger = new TestPki(dir, "stranger");
    }

    @AfterEach
    void stop() {
        if (gateway != null) {
            gateway.close();
        }
    }

    private int start(Map<String, String> extra) throws Exception {
        return start(extra, AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED));
    }

    private int start(Map<String, String> extra, NasRegistry registry) throws Exception {
        Path users = Files.writeString(dir.resolve("users"), "nemo    Cleartext-Password := \"arctangent\"\n");
        Map<String, String> settings = new HashMap<>(Map.of(
                "auth.stores",
                "local",
                "auth.store.local.type",
                "file",
                "auth.store.local.path",
                users.toString(),
                "auth.plugins.dir",
                dir.resolve("no-plugins").toString(),
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
                "nas.local.radsec",
                "true"));
        settings.putAll(extra);
        Config config = Config.of(settings);
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        gateway = Gateway.launchWith(
                gatewayConfig(),
                registry,
                auth,
                Gateway.storeHandler(config, auth),
                RadsecConfig.from(config, "127.0.0.1"));
        return gateway.radsecPort();
    }

    private RadsecClient connect(int port, String cn, String protocol) throws Exception {
        return new RadsecClient(port, TestPki.clientContext(pki.client(cn), pki.ca), protocol);
    }

    @Test
    void accessRequestsAndStatusServerOverTls13And12() throws Exception {
        int port = start(Map.of());
        for (String protocol : new String[] {"TLSv1.3", "TLSv1.2"}) {
            try (RadsecClient client = connect(port, "nas-1", protocol)) {
                byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false, RADSEC);
                client.send(good);
                AuthAgentTest.assertSignedReplyTo(client.receive(), good, RadiusCode.ACCESS_ACCEPT, RADSEC);

                byte[] wrong = AuthAgentTest.accessRequest(2, "wrong", true, false, RADSEC);
                client.send(wrong);
                AuthAgentTest.assertSignedReplyTo(client.receive(), wrong, RadiusCode.ACCESS_REJECT, RADSEC);

                byte[] status = statusServer(3);
                client.send(status);
                assertThat(client.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
            }
        }
        RadsecAgent agent = gateway.radsecAgent();
        assertThat(agent.get(RadsecAgent.Counter.REPLIES)).isEqualTo(6);
        assertThat(gateway.metrics())
                .contains("radiusward_gateway_radsec_total{gateway=\"1\",result=\"connections_accepted\"} 2");
    }

    @Test
    void manyRequestsInFlightOnOneConnection() throws Exception {
        int port = start(Map.of());
        try (RadsecClient client = connect(port, "nas-1", "TLSv1.3")) {
            Map<Integer, byte[]> sent = new HashMap<>();
            for (int id = 0; id < 200; id++) {
                byte[] request = AuthAgentTest.accessRequest(id, id % 2 == 0 ? "arctangent" : "x", true, false, RADSEC);
                sent.put(id, request);
                client.send(request); // all written before any reply is read
            }
            for (int i = 0; i < 200; i++) {
                byte[] reply = client.receive();
                int id = reply[1] & 0xFF;
                AuthAgentTest.assertSignedReplyTo(
                        reply,
                        sent.remove(id),
                        id % 2 == 0 ? RadiusCode.ACCESS_ACCEPT : RadiusCode.ACCESS_REJECT,
                        RADSEC);
            }
            assertThat(sent).isEmpty();
        }
    }

    @Test
    void clientCertificatesAreRequiredAndChecked() throws Exception {
        int port = start(Map.of());
        assertThatThrownBy(() -> new RadsecClient(port, TestPki.clientContext(null, pki.ca), "TLSv1.2"))
                .as("no client certificate")
                .isInstanceOf(IOException.class);
        assertThatThrownBy(() ->
                        new RadsecClient(port, TestPki.clientContext(stranger.client("nas-1"), pki.ca), "TLSv1.2"))
                .as("a certificate of another CA")
                .isInstanceOf(IOException.class);
        LocalWait.until(() -> gateway.radsecAgent().get(RadsecAgent.Counter.HANDSHAKES_FAILED) == 2);
        assertThat(gateway.radsecAgent().openConnections()).isZero();
    }

    @Test
    void theCertificateMustNameTheNasWhenConfigured() throws Exception {
        int port = start(Map.of("nas.local.radsec.identity", "nas-1.corp.test"));
        try (RadsecClient other = connect(port, "nas-2.corp.test", "TLSv1.3")) {
            other.send(AuthAgentTest.accessRequest(1, "arctangent", true, false, RADSEC));
            assertThat(other.closedByServer()).isTrue();
        }
        try (RadsecClient right = connect(port, "nas-1.corp.test", "TLSv1.3")) {
            byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false, RADSEC);
            right.send(good);
            assertThat(right.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
        }
        assertThat(gateway.radsecAgent().get(RadsecAgent.Counter.NAS_REFUSED)).isEqualTo(1);
    }

    @Test
    void aNasEntryWithoutRadsecIsRefused() throws Exception {
        NasClient local = AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED)
                .clients()
                .iterator()
                .next();
        NasClient other = new NasClient(
                "other", 2002, 0x0A000000, 8, RADSEC, "default", NasClient.MessageAuthenticatorPolicy.OPTIONAL);
        int port = start(
                Map.of("nas.local.radsec", "false", "nas.other.radsec", "true"),
                NasRegistry.of(java.util.List.of(local, other)));
        try (RadsecClient client = connect(port, "nas-1", "TLSv1.3")) {
            client.send(AuthAgentTest.accessRequest(1, "arctangent", true, false, RADSEC));
            assertThat(client.closedByServer()).isTrue();
        }
    }

    @Test
    void aNasIdentifiedByItsCertificateAlone() throws Exception {
        NasClient roaming = new NasClient(
                "roaming",
                3003,
                0,
                -1,
                new byte[0],
                "default",
                NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                new NasClient.Identity[0],
                0,
                NasClient.MessageAuthenticatorPolicy.REQUIRED);
        NasRegistry registry = NasRegistry.of(java.util.List.of(roaming));
        assertThat(registry.lookup(java.net.InetAddress.getLoopbackAddress()))
                .as("never found by address")
                .isNull();
        int port = start(
                Map.of(
                        "nas.local.radsec",
                        "false",
                        "nas.roaming.radsec",
                        "true",
                        "nas.roaming.radsec.identity",
                        "wlc.roaming.test"),
                registry);
        try (RadsecClient client = connect(port, "wlc.roaming.test", "TLSv1.3")) {
            byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false, RADSEC);
            client.send(good);
            AuthAgentTest.assertSignedReplyTo(client.receive(), good, RadiusCode.ACCESS_ACCEPT, RADSEC);
        }
        try (RadsecClient other = connect(port, "wlc.elsewhere.test", "TLSv1.3")) {
            other.send(AuthAgentTest.accessRequest(1, "arctangent", true, false, RADSEC));
            assertThat(other.closedByServer()).isTrue();
        }
    }

    @Test
    void reconnectsResumeTheirTlsSession() throws Exception {
        int port = start(Map.of());
        for (String protocol : new String[] {"TLSv1.2", "TLSv1.3"}) {
            javax.net.ssl.SSLContext context = TestPki.clientContext(pki.client("nas-1"), pki.ca);
            long before = gateway.radsecAgent().get(RadsecAgent.Counter.HANDSHAKES_RESUMED);
            for (int i = 0; i < 3; i++) {
                try (RadsecClient client = new RadsecClient(port, context, protocol)) {
                    byte[] good = AuthAgentTest.accessRequest(i, "arctangent", true, false, RADSEC);
                    client.send(good);
                    assertThat(client.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
                }
                Thread.sleep(20); // the session's creation time must be older than the next accept
            }
            assertThat(gateway.radsecAgent().get(RadsecAgent.Counter.HANDSHAKES_RESUMED) - before)
                    .as(protocol + ": the second and third connection resumed")
                    .isEqualTo(2);
        }
    }

    @Test
    void expiredSessionsAreNotResumed() throws Exception {
        int port = start(Map.of("radsec.session.timeout", "1s"));
        javax.net.ssl.SSLContext context = TestPki.clientContext(pki.client("nas-1"), pki.ca);
        for (int i = 0; i < 2; i++) {
            try (RadsecClient client = new RadsecClient(port, context, "TLSv1.2")) {
                client.send(AuthAgentTest.accessRequest(i, "arctangent", true, false, RADSEC));
                assertThat(client.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
            }
            Thread.sleep(2_100);
        }
        assertThat(gateway.radsecAgent().get(RadsecAgent.Counter.HANDSHAKES_RESUMED))
                .as("the certificate is checked again after radsec.session.timeout")
                .isZero();
    }

    @Test
    void malformedPacketsCloseTheConnectionOthersAreIgnored() throws Exception {
        int port = start(Map.of());
        try (RadsecClient client = connect(port, "nas-1", "TLSv1.3")) {
            byte[] disconnect = AuthAgentTest.accessRequest(9, "arctangent", true, false, RADSEC);
            disconnect[0] = 40; // Disconnect-Request: not ours to answer, the connection stays
            client.send(disconnect);
            byte[] good = AuthAgentTest.accessRequest(10, "arctangent", true, false, RADSEC);
            client.send(good);
            assertThat(client.receive()[1]).isEqualTo((byte) 10);

            client.send(new byte[] {1, 11, 0, 3}); // a length below the header
            assertThat(client.closedByServer()).isTrue();
        }
        assertThat(gateway.radsecAgent().get(RadsecAgent.Counter.NOT_HANDLED)).isEqualTo(1);
        assertThat(gateway.radsecAgent().get(RadsecAgent.Counter.MALFORMED)).isEqualTo(1);
    }

    @Test
    void handshakesThatNeverFinishTimeOut() throws Exception {
        int port = start(Map.of("radsec.handshake.timeout", "200ms"));
        try (java.net.Socket silent = new java.net.Socket("127.0.0.1", port)) {
            silent.setSoTimeout(3_000);
            byte[] rest = silent.getInputStream().readAllBytes(); // until the gateway closes it
            assertThat(rest.length).as("at most a TLS alert before the end").isLessThan(64);
        }
        assertThat(gateway.radsecAgent().get(RadsecAgent.Counter.TIMED_OUT)).isEqualTo(1);
    }

    static byte[] statusServer(int identifier) {
        byte[] authenticator = new byte[16];
        ThreadLocalRandom.current().nextBytes(authenticator);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[64]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.STATUS_SERVER, identifier)
                .authenticator(authenticator);
        int ma = enc.messageAuthenticator();
        int length = enc.finish();
        new RadiusAuthenticator().signAccessRequest(buffer, 0, length, ma, RADSEC);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** Polls a condition for up to five seconds. */
    static final class LocalWait {
        static void until(java.util.function.BooleanSupplier condition) throws InterruptedException {
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (!condition.getAsBoolean()) {
                if (System.nanoTime() > deadline) {
                    throw new AssertionError("condition not met within 5 s");
                }
                Thread.sleep(10);
            }
        }
    }

    static GatewayConfig gatewayConfig() {
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        return new GatewayConfig(
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
                new File(dir.toFile(), "aeron-" + System.nanoTime()).getPath(),
                c.dictionaryDir(),
                c.debugResponseDelay());
    }
}
