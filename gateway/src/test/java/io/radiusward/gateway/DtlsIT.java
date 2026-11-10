/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusCode;
import java.io.File;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * RADIUS over DTLS 1.2 (RFC 7360, ADR 0038) through the real gateway, with the JDK's DTLS as the NAS: Access-Requests
 * and Status-Server with the secret {@code radius/dtls}, many in flight; lost handshake flights retransmitted by the
 * gateway's timer; client certificates required and checked; a restarted NAS replacing its association; datagrams
 * outside DTLS and malformed packets discarded without closing; idle associations closed. Accounting over DTLS with a
 * cluster: {@code RadsecAccountingIT}; interop with radsecproxy: {@code RadsecproxyIT}.
 */
class DtlsIT {

    static final byte[] DTLS = "radius/dtls".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    static Path dir;

    static TestPki pki;
    static TestPki stranger;

    private Gateway gateway;

    @BeforeAll
    static void certificates() throws Exception {
        pki = new TestPki(dir, "dtls");
        stranger = new TestPki(dir, "dtls-stranger");
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
                "nas.local.dtls",
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
        return gateway.dtlsPort();
    }

    private DtlsClient connect(int port, String cn) throws Exception {
        return new DtlsClient(port, TestPki.clientContext(pki.client(cn), pki.ca, "DTLS"));
    }

    private RadsecAgent agent() {
        return gateway.radsecAgent();
    }

    @Test
    void accessRequestsAndStatusServerOverDtls() throws Exception {
        int port = start(Map.of());
        assertThat(gateway.radsecPort()).as("no TCP listener").isEqualTo(-1);
        try (DtlsClient client = connect(port, "nas-1")) {
            byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false, DTLS);
            client.send(good);
            AuthAgentTest.assertSignedReplyTo(client.receive(), good, RadiusCode.ACCESS_ACCEPT, DTLS);

            byte[] wrong = AuthAgentTest.accessRequest(2, "wrong", true, false, DTLS);
            client.send(wrong);
            AuthAgentTest.assertSignedReplyTo(client.receive(), wrong, RadiusCode.ACCESS_REJECT, DTLS);

            client.send(AuthAgentTest.statusServer(3, true, DTLS));
            assertThat(client.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);

            Map<Integer, byte[]> sent = new HashMap<>();
            for (int id = 10; id < 60; id++) {
                byte[] request = AuthAgentTest.accessRequest(id, id % 2 == 0 ? "arctangent" : "x", true, false, DTLS);
                sent.put(id, request);
                client.send(request); // all sent before any reply is read
            }
            for (int i = 0; i < 50; i++) {
                byte[] reply = client.receive();
                int id = reply[1] & 0xFF;
                AuthAgentTest.assertSignedReplyTo(
                        reply,
                        sent.remove(id),
                        id % 2 == 0 ? RadiusCode.ACCESS_ACCEPT : RadiusCode.ACCESS_REJECT,
                        DTLS);
            }
            assertThat(sent).isEmpty();
        }
        assertThat(agent().getDtls(RadsecAgent.Counter.REPLIES)).isEqualTo(53);
        assertThat(gateway.metrics())
                .contains("radiusward_gateway_dtls_total{gateway=\"1\",result=\"connections_accepted\"} 1")
                .contains("radiusward_gateway_dtls_total{gateway=\"1\",result=\"requests\"} 53");
        RadsecIT.LocalWait.until(() -> agent().openAssociations() == 0); // close_notify ends the association
    }

    @Test
    void lostHandshakeFlightsAreRetransmittedByTheGateway() throws Exception {
        int port = start(Map.of("radsec.dtls.retransmit", "300ms"));
        // the NAS loses the gateway's second and third datagrams and never retransmits itself
        DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        try (DtlsClient client = new DtlsClient(
                port, TestPki.clientContext(pki.client("nas-1"), pki.ca, "DTLS"), socket, new int[] {2, 3}, false)) {
            byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false, DTLS);
            client.send(good);
            AuthAgentTest.assertSignedReplyTo(client.receive(), good, RadiusCode.ACCESS_ACCEPT, DTLS);
        }
        assertThat(agent().getDtls(RadsecAgent.Counter.RETRANSMISSIONS)).isPositive();
    }

    @Test
    void clientCertificatesAreRequiredAndChecked() throws Exception {
        int port = start(Map.of("nas.local.dtls.identity", "nas-1.corp.test", "radsec.dtls.retransmit", "200ms"));
        javax.net.ssl.SSLContext withoutCertificate = TestPki.clientContext(null, pki.ca, "DTLS");
        javax.net.ssl.SSLContext otherCa = TestPki.clientContext(stranger.client("nas-1"), pki.ca, "DTLS");
        assertThatThrownBy(() -> new DtlsClient(port, withoutCertificate))
                .as("no client certificate")
                .isInstanceOf(Exception.class);
        assertThatThrownBy(() -> new DtlsClient(port, otherCa))
                .as("a certificate of another CA")
                .isInstanceOf(Exception.class);
        RadsecIT.LocalWait.until(() -> agent().getDtls(RadsecAgent.Counter.HANDSHAKES_FAILED) == 2);

        try (DtlsClient other = connect(port, "nas-2.corp.test")) { // the handshake succeeds, the NAS does not
            other.send(AuthAgentTest.accessRequest(1, "arctangent", true, false, DTLS));
            assertThat(other.receive(1_000)).isNull();
        }
        assertThat(agent().getDtls(RadsecAgent.Counter.NAS_REFUSED)).isEqualTo(1);
        try (DtlsClient right = connect(port, "nas-1.corp.test")) {
            byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false, DTLS);
            right.send(good);
            assertThat(right.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
        }
    }

    @Test
    void aRestartedNasReplacesItsAssociation() throws Exception {
        int port = start(Map.of());
        DtlsClient before = connect(port, "nas-1");
        byte[] first = AuthAgentTest.accessRequest(1, "arctangent", true, false, DTLS);
        before.send(first);
        assertThat(before.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
        int localPort = before.localPort();
        before.abandon(); // power lost: no close_notify

        DatagramSocket same = new DatagramSocket(localPort, InetAddress.getLoopbackAddress());
        try (DtlsClient after =
                new DtlsClient(port, TestPki.clientContext(pki.client("nas-1"), pki.ca, "DTLS"), same, null, true)) {
            byte[] again = AuthAgentTest.accessRequest(2, "arctangent", true, false, DTLS);
            after.send(again);
            AuthAgentTest.assertSignedReplyTo(after.receive(), again, RadiusCode.ACCESS_ACCEPT, DTLS);
        }
        assertThat(agent().getDtls(RadsecAgent.Counter.RESTARTED)).isEqualTo(1);
    }

    @Test
    void datagramsOutsideDtlsAndMalformedPacketsAreDiscarded() throws Exception {
        int port = start(Map.of());
        try (DtlsClient client = connect(port, "nas-1")) {
            client.send(new byte[] {1, 11, 0, 3}); // a length below the header
            byte[] good = AuthAgentTest.accessRequest(4, "arctangent", true, false, DTLS);
            client.send(good);
            AuthAgentTest.assertSignedReplyTo(client.receive(), good, RadiusCode.ACCESS_ACCEPT, DTLS);
        }
        try (DatagramSocket plain = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            byte[] radius = AuthAgentTest.accessRequest(5, "arctangent", true, false, DTLS);
            plain.send(new java.net.DatagramPacket(radius, radius.length, InetAddress.getLoopbackAddress(), port));
        }
        RadsecIT.LocalWait.until(() -> agent().getDtls(RadsecAgent.Counter.NOT_ASSOCIATED) == 1);
        assertThat(agent().getDtls(RadsecAgent.Counter.MALFORMED)).isEqualTo(1);
        assertThat(agent().getDtls(RadsecAgent.Counter.CONNECTIONS_ACCEPTED)).isEqualTo(1);
    }

    @Test
    void idleAssociationsAndUnfinishedHandshakesTimeOut() throws Exception {
        int port = start(Map.of("radsec.dtls.idle.timeout", "300ms", "radsec.handshake.timeout", "300ms"));
        DtlsClient client = connect(port, "nas-1");
        byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false, DTLS);
        client.send(good);
        assertThat(client.receive()[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
        client.abandon();
        RadsecIT.LocalWait.until(() -> agent().openAssociations() == 0);

        // a ClientHello and nothing after it
        try (DatagramSocket half = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            javax.net.ssl.SSLEngine e =
                    TestPki.clientContext(pki.client("nas-1"), pki.ca, "DTLS").createSSLEngine();
            e.setUseClientMode(true);
            e.beginHandshake();
            java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(1 << 16);
            e.wrap(java.nio.ByteBuffer.allocate(0), out);
            half.send(new java.net.DatagramPacket(out.array(), out.position(), InetAddress.getLoopbackAddress(), port));
            RadsecIT.LocalWait.until(() -> agent().getDtls(RadsecAgent.Counter.CONNECTIONS_ACCEPTED) == 2);
            RadsecIT.LocalWait.until(() -> agent().openAssociations() == 0);
        }
        assertThat(agent().getDtls(RadsecAgent.Counter.TIMED_OUT)).isEqualTo(2);
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
        int port = start(
                Map.of(
                        "nas.local.dtls",
                        "false",
                        "nas.roaming.dtls",
                        "true",
                        "nas.roaming.dtls.identity",
                        "ap.roam.test"),
                NasRegistry.of(java.util.List.of(roaming)));
        try (DtlsClient client = connect(port, "ap.roam.test")) {
            byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false, DTLS);
            client.send(good);
            AuthAgentTest.assertSignedReplyTo(client.receive(), good, RadiusCode.ACCESS_ACCEPT, DTLS);
        }
        try (DtlsClient other = connect(port, "ap.elsewhere.test")) {
            other.send(AuthAgentTest.accessRequest(2, "arctangent", true, false, DTLS));
            assertThat(other.receive(1_000))
                    .as("its certificate names no entry")
                    .isNull();
        }
        assertThat(agent().getDtls(RadsecAgent.Counter.NAS_REFUSED)).isEqualTo(1);
    }

    @Test
    void radsecAndDtlsTogether() throws Exception {
        int port = start(Map.of("radsec.enabled", "true", "radsec.port", "0", "nas.local.radsec", "true"));
        try (DtlsClient dtls = connect(port, "nas-1");
                RadsecClient tcp = new RadsecClient(
                        gateway.radsecPort(), TestPki.clientContext(pki.client("nas-1"), pki.ca), "TLSv1.3")) {
            byte[] overDtls = AuthAgentTest.accessRequest(1, "arctangent", true, false, DTLS);
            dtls.send(overDtls);
            AuthAgentTest.assertSignedReplyTo(dtls.receive(), overDtls, RadiusCode.ACCESS_ACCEPT, DTLS);
            byte[] overTcp = AuthAgentTest.accessRequest(1, "arctangent", true, false, RadsecIT.RADSEC);
            tcp.send(overTcp);
            AuthAgentTest.assertSignedReplyTo(tcp.receive(), overTcp, RadiusCode.ACCESS_ACCEPT, RadsecIT.RADSEC);
        }
    }

    private GatewayConfig gatewayConfig() {
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
