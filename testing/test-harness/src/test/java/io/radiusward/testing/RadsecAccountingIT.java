/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import io.radiusward.gateway.AuthConfig;
import io.radiusward.gateway.DtlsClient;
import io.radiusward.gateway.Gateway;
import io.radiusward.gateway.RadsecClient;
import io.radiusward.gateway.RadsecConfig;
import io.radiusward.gateway.TestPki;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.tools.admin.AdminClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Accounting over RadSec (ADR 0034), DTLS (ADR 0038) and plain TCP (ADR 0045) with 3 cluster members: answered only after the commit, signed
 * with the secret of the transport, and the same event later over another transport from the same NAS entry is a
 * duplicate — one NAS, one set of keys, whichever transport it uses.
 */
@Epic("Transports")
@Feature("Accounting over RadSec, DTLS and TCP")
@Link(name = "ADR 0034", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0034-radsec.md")
@Link(name = "ADR 0038", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0038-dtls.md")
@Link(
        name = "ADR 0045",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0045-radius-over-tcp.md")
class RadsecAccountingIT {

    static final byte[] RADSEC = "radsec".getBytes(StandardCharsets.US_ASCII);
    static final byte[] DTLS = "radius/dtls".getBytes(StandardCharsets.US_ASCII);
    static final byte[] UDP_SECRET = LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private LocalCluster cluster;

    @AfterEach
    void close() {
        if (cluster != null) {
            cluster.close();
        }
    }

    @Test
    void accountingOverRadsecIsCommittedAndDeduplicatedWithUdp() throws Exception {
        TestPki pki = new TestPki(dir, "radsec");
        cluster = LocalCluster.start(dir.toFile(), 3, 0);
        cluster.awaitLeader();
        RadsecConfig radsec = RadsecConfig.from(
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
                "127.0.0.1");
        Gateway gateway = cluster.startGateway(
                1, LocalCluster.freePort(), LocalCluster.registry(), AuthConfig.DISABLED, d -> null, radsec);
        cluster.awaitGatewaysConnected();

        try (RadsecClient nas =
                new RadsecClient(gateway.radsecPort(), TestPki.clientContext(pki.client("nas"), pki.ca), "TLSv1.3")) {
            byte[] start = request(1, 1, "rs-1", 0, RADSEC);
            nas.send(start);
            assertResponse(nas.receive(), start, RADSEC);
            byte[] interim = request(2, 3, "rs-1", 60, RADSEC);
            nas.send(interim);
            assertResponse(nas.receive(), interim, RADSEC);

            byte[] status = statusServer(3, RADSEC);
            nas.send(status);
            assertResponse(nas.receive(), status, RADSEC);
        }

        LocalClusterIT udp = new LocalClusterIT();
        try {
            byte[] sameStart = request(7, 1, "rs-1", 0, UDP_SECRET);
            udp.exchange(gateway.radiusPort(), sameStart); // verified with the UDP secret
        } finally {
            udp.close();
        }
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied()).as("Start and Interim").isEqualTo(2);
            assertThat(state.duplicates()).as("the Start again, over UDP").isEqualTo(1);
        }
    }

    static void assertResponse(byte[] response, byte[] request, byte[] secret) {
        RadiusPacket view = new RadiusPacket();
        view.wrap(new UnsafeBuffer(response), 0, response.length);
        assertThat(view.code()).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
        assertThat(view.identifier()).isEqualTo(request[1] & 0xFF);
        assertThat(new RadiusAuthenticator().verifyResponse(view, new UnsafeBuffer(request), 4, secret))
                .isTrue();
    }

    static byte[] request(int id, int status, String sessionId, long sessionTime, byte[] secret) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id)
                .uint32(40, status)
                .attribute(44, sessionId)
                .uint32(55, 1_780_000_000L);
        if (status != 1) {
            enc.uint32(46, sessionTime).uint32(42, sessionTime * 1000);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, secret);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    @Test
    void accountingOverDtlsRadsecAndUdpIsOneSetOfSessions() throws Exception {
        TestPki pki = new TestPki(dir, "dtls");
        cluster = LocalCluster.start(dir.toFile(), 3, 0);
        cluster.awaitLeader();
        RadsecConfig radsec = RadsecConfig.from(
                Config.of(Map.ofEntries(
                        Map.entry("radsec.enabled", "true"),
                        Map.entry("radsec.port", "0"),
                        Map.entry("radsec.dtls.enabled", "true"),
                        Map.entry("radsec.dtls.port", "0"),
                        Map.entry("radsec.certificate", pki.serverPem.toString()),
                        Map.entry("radsec.key", pki.serverKey.toString()),
                        Map.entry("radsec.ca", pki.caPem.toString()),
                        Map.entry("nas." + LocalCluster.NAS_NAME + ".radsec", "true"),
                        Map.entry("nas." + LocalCluster.NAS_NAME + ".dtls", "true"),
                        Map.entry("radius.tcp.enabled", "true"),
                        Map.entry("radius.tcp.auth.port", "0"),
                        Map.entry("radius.tcp.acct.port", "0"),
                        Map.entry("nas." + LocalCluster.NAS_NAME + ".tcp", "true"))),
                "127.0.0.1");
        Gateway gateway = cluster.startGateway(
                1, LocalCluster.freePort(), LocalCluster.registry(), AuthConfig.DISABLED, d -> null, radsec);
        cluster.awaitGatewaysConnected();

        try (DtlsClient nas =
                new DtlsClient(gateway.dtlsPort(), TestPki.clientContext(pki.client("nas"), pki.ca, "DTLS"))) {
            byte[] start = request(1, 1, "dt-1", 0, DTLS);
            nas.send(start);
            assertResponse(nas.receive(), start, DTLS);
            byte[] status = statusServer(2, DTLS);
            nas.send(status);
            assertResponse(nas.receive(), status, DTLS);
        }
        try (RadsecClient nas =
                new RadsecClient(gateway.radsecPort(), TestPki.clientContext(pki.client("nas"), pki.ca), "TLSv1.3")) {
            byte[] interim = request(3, 3, "dt-1", 60, RADSEC);
            nas.send(interim);
            assertResponse(nas.receive(), interim, RADSEC);
        }
        try (java.net.Socket tcp = new java.net.Socket("127.0.0.1", gateway.tcpPort(false))) {
            tcp.setSoTimeout(5_000);
            byte[] interim = request(4, 3, "dt-1", 120, UDP_SECRET); // plain TCP: the NAS entry's own secret
            tcp.getOutputStream().write(interim);
            byte[] answer = new byte[20];
            new java.io.DataInputStream(tcp.getInputStream()).readFully(answer);
            assertResponse(answer, interim, UDP_SECRET);
        }
        LocalClusterIT udp = new LocalClusterIT();
        try {
            udp.exchange(gateway.radiusPort(), request(7, 1, "dt-1", 0, UDP_SECRET));
        } finally {
            udp.close();
        }
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied())
                    .as("Start over DTLS, Interims over RadSec and plain TCP")
                    .isEqualTo(3);
            assertThat(state.duplicates()).as("the Start again, over UDP").isEqualTo(1);
            assertThat(state.active()).isEqualTo(1);
        }
    }

    static byte[] statusServer(int id, byte[] secret) {
        byte[] authenticator = new byte[16];
        ThreadLocalRandom.current().nextBytes(authenticator);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[64]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.STATUS_SERVER, id)
                .authenticator(authenticator);
        int ma = enc.messageAuthenticator();
        int length = enc.finish();
        new RadiusAuthenticator().signAccessRequest(buffer, 0, length, ma, secret);
        return Arrays.copyOf(buffer.byteArray(), length);
    }
}
