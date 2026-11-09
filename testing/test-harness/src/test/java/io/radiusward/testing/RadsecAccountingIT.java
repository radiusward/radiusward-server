/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import io.radiusward.gateway.AuthConfig;
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
 * Accounting over RadSec (ADR 0034) with 3 cluster members: answered only after the commit, signed with the RadSec
 * secret, and the same event later over UDP from the same NAS entry is a duplicate — one NAS, one set of keys,
 * whichever transport it uses.
 */
class RadsecAccountingIT {

    static final byte[] RADSEC = "radsec".getBytes(StandardCharsets.US_ASCII);
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

            byte[] status = statusServer(3);
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

    static byte[] statusServer(int id) {
        byte[] authenticator = new byte[16];
        ThreadLocalRandom.current().nextBytes(authenticator);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[64]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.STATUS_SERVER, id)
                .authenticator(authenticator);
        int ma = enc.messageAuthenticator();
        int length = enc.finish();
        new RadiusAuthenticator().signAccessRequest(buffer, 0, length, ma, RADSEC);
        return Arrays.copyOf(buffer.byteArray(), length);
    }
}
