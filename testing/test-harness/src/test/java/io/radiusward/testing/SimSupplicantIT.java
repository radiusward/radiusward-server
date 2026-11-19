/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.client.EapLogin;
import io.radiusward.client.EapResult;
import io.radiusward.client.PacketBuilder;
import io.radiusward.client.RadiusClient;
import io.radiusward.client.SimCard;
import io.radiusward.cluster.node.LogPurgeConfig;
import io.radiusward.common.config.Config;
import io.radiusward.server.AuthConfig;
import io.radiusward.server.RadiusServer;
import io.radiusward.tools.admin.AdminClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The published supplicant's EAP-SIM, EAP-AKA and EAP-AKA′ ({@code radiusward-client}, {@link SimCard}) against a
 * RADIUS server on a three-member cluster, which keeps AKA's sequence numbers: each method accepted with the device's MSK equal to
 * the NAS's, the network proved to the card, a card ahead of the network resynchronised, and a wrong key or an unknown
 * IMSI rejected.
 */
@Epic("EAP")
@Feature("EAP supplicant: SIM and AKA")
class SimSupplicantIT {

    static final byte[] KI = HexFormat.of().parseHex("465b5ce8b199b49faa5f0a2ee238a6bc");
    static final byte[] OPC = HexFormat.of().parseHex("cd63cb71954a9f4e48a5994e37a02baf");
    static final byte[] OP = HexFormat.of().parseHex("cdc202d5123e20f62b6d676ac72cb318");

    @TempDir
    static Path dir;

    static LocalCluster cluster;
    static RadiusClient client;

    @BeforeAll
    static void start() throws Exception {
        Path users = Files.writeString(dir.resolve("users"), """
                262011000000001  SIM-Ki := 0x%1$s, SIM-OPc := 0x%2$s
                                 Reply-Message = "welcome, SIM 1"
                262011000000002  SIM-Ki := 0x%1$s, SIM-OP := 0x%3$s
                                 Reply-Message = "welcome, SIM 2"
                """.formatted(hex(KI), hex(OPC), hex(OP)));
        cluster = LocalCluster.builder(dir.resolve("cluster").toFile())
                .members(3)
                .radiusServers(0)
                .purge(new LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)))
                .start();
        Config settings = Config.of(Map.of(
                "auth.stores", "sims",
                "auth.store.sims.type", "file",
                "auth.store.sims.path", users.toString(),
                "auth.plugins.dir", dir.resolve("plugins").toString(),
                "auth.eap.methods", "sim, aka, aka-prime",
                "auth.reject.delay", "0s"));
        AuthConfig auth = new AuthConfig(
                true, 0, 2, 256, 4096, Duration.ofSeconds(10), Duration.ofSeconds(2), Duration.ofSeconds(30));
        RadiusServer server =
                cluster.startServer(1, 0, LocalCluster.registry(), auth, RadiusServer.storeHandler(settings, auth));
        cluster.awaitLeader();
        cluster.awaitServersConnected();
        try (FakeNas nas = new FakeNas()) {
            // the log needs a recording before the member reports its state version
            nas.reply(
                    server.radiusPort(),
                    PacketBuilder.accountingRequest(1)
                            .uint32(40, 1)
                            .attribute(44, "warm-up")
                            .attribute(1, "nobody")
                            .uint32(55, AccountingRequest.EVENT_TIMESTAMP)
                            .secret(LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII))
                            .build());
        }
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "state version 8 activated",
                    () -> admin.state().activeVersion() >= 8);
        }
        client = RadiusClient.udp("127.0.0.1", server.authPort(), LocalCluster.SECRET)
                .timeout(Duration.ofSeconds(2))
                .retries(2);
    }

    @AfterAll
    static void stop() {
        if (client != null) {
            client.close();
        }
        if (cluster != null) {
            cluster.close();
        }
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    private static void acceptedWithKeys(EapResult r, String welcome) {
        assertThat(r.accepted()).as(r.toString()).isTrue();
        assertThat(r.response().orElseThrow().string(18)).contains(welcome);
        assertThat(r.serverProved()).as("the network proved itself to the card").isTrue();
        assertThat(r.msk()).as("the device's MSK").isPresent();
        assertThat(r.serverMsk().orElseThrow()).isEqualTo(r.msk().orElseThrow());
    }

    @Test
    void simWithGsmTripletsFromMilenage() {
        acceptedWithKeys(client.eap(EapLogin.sim(new SimCard("262011000000001", KI, OPC))), "welcome, SIM 1");
        acceptedWithKeys(
                client.eap(EapLogin.sim(SimCard.withOp("262011000000002", KI, OP))
                        .realm("wlan.mnc001.mcc262.3gppnetwork.org")),
                "welcome, SIM 2");
    }

    @Test
    void akaAndTheCardKeepsTheSequence() {
        SimCard card = new SimCard("262011000000001", KI, OPC);
        acceptedWithKeys(client.eap(EapLogin.aka(card)), "welcome, SIM 1");
        long first = card.sqn();
        assertThat(first).as("the SQN the card accepted").isPositive();
        acceptedWithKeys(client.eap(EapLogin.aka(card)), "welcome, SIM 1");
        assertThat(card.sqn()).as("a fresh SQN each time").isGreaterThan(first);
    }

    @Test
    void akaPrimeBindsTheNetworkName() {
        acceptedWithKeys(client.eap(EapLogin.akaPrime(new SimCard("262011000000002", KI, OPC))), "welcome, SIM 2");
    }

    @Test
    void aCardAheadOfTheNetworkResynchronises() {
        SimCard card = new SimCard("262011000000001", KI, OPC).sqn(1L << 40);
        EapResult r = client.eap(EapLogin.aka(card));
        acceptedWithKeys(r, "welcome, SIM 1");
        assertThat(card.sqn()).as("the network went on from the card's SQN").isGreaterThan(1L << 40);
    }

    @Test
    void aWrongKeyOrAnUnknownImsiIsRejected() {
        byte[] otherKi = KI.clone();
        otherKi[0] ^= 1;
        EapResult aka = client.eap(EapLogin.aka(new SimCard("262011000000001", otherKi, OPC)));
        assertThat(aka.rejected()).as("the card rejects the network's AUTN").isTrue();
        assertThat(aka.serverProved()).isFalse();
        assertThat(client.eap(EapLogin.sim(new SimCard("262011000000001", otherKi, OPC)))
                        .rejected())
                .as("the server's MAC does not verify on the card")
                .isTrue();
        assertThat(client.eap(EapLogin.akaPrime(new SimCard("262019999999999", KI, OPC)))
                        .rejected())
                .isTrue();
    }
}
