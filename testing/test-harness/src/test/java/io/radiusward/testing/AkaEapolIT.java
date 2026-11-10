/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import io.radiusward.gateway.AuthConfig;
import io.radiusward.gateway.CoaConfig;
import io.radiusward.gateway.Gateway;
import io.radiusward.gateway.NasClient;
import io.radiusward.gateway.NasRegistry;
import io.radiusward.gateway.ProxyConfig;
import io.radiusward.gateway.RadsecConfig;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.tools.admin.AdminClient;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

/**
 * EAP-AKA, EAP-AKA′ and EAP-SIM against wpa_supplicant's {@code eapol_test} with its simulated SIM/USIM (ADR 0061): a
 * three-member
 * cluster keeps the sequence numbers, one gateway computes the vectors from the subscribers' Ki and OPc (3GPP test set
 * 1). Covers both methods, a USIM ahead of the server (resynchronisation), an anonymous outer identity, a subscriber
 * stored with OP, a wrong key and an unknown IMSI. Skipped where Docker is missing, a failure where it is required.
 */
class AkaEapolIT {

    static final String SECRET = "testing123";
    static final String KI = "465b5ce8b199b49faa5f0a2ee238a6bc";
    static final String OPC = "cd63cb71954a9f4e48a5994e37a02baf";
    static final String OP = "cdc202d5123e20f62b6d676ac72cb318";
    static final String REALM = "@wlan.mnc001.mcc262.3gppnetwork.org";

    @TempDir
    static Path dir;

    static LocalCluster cluster;
    static Gateway gateway;
    static GenericContainer<?> peer;

    @BeforeAll
    static void start() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        Path image = Path.of("../eapol-test").toAbsolutePath().normalize();
        peer = new GenericContainer<>(new ImageFromDockerfile("radiusward-eapol-test:test", false)
                        .withFileFromPath("Dockerfile", image.resolve("Dockerfile")))
                .withExtraHost("host.docker.internal", "host-gateway");
        peer.start();

        Path users = Files.writeString(dir.resolve("users"), """
                262011000000001  SIM-Ki := 0x%1$s, SIM-OPc := 0x%2$s
                                 Reply-Message = "welcome, SIM 1"
                262011000000002  SIM-Ki := 0x%1$s, SIM-OP := 0x%3$s, SIM-AMF := 0x8000
                262011000000003  SIM-Ki := 0x%1$s, SIM-OPc := 0x%2$s
                262011000000004  SIM-Ki := 0x%1$s, SIM-OPc := 0x%2$s
                262011000000005  SIM-Ki := 0x%1$s, SIM-OPc := 0x%2$s
                262011000000006  SIM-Ki := 0x%1$s, SIM-OPc := 0x%2$s
                262011000000007  %4$s
                """.formatted(KI, OPC, OP, StoredTriplets.items()));
        cluster = LocalCluster.start(
                dir.resolve("cluster").toFile(),
                3,
                0,
                LocalCluster.freePortBase(3),
                new int[0],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)));
        Config settings = Config.of(Map.of(
                "auth.stores", "sims",
                "auth.store.sims.type", "file",
                "auth.store.sims.path", users.toString(),
                "auth.plugins.dir", dir.resolve("plugins").toString(),
                "auth.eap.methods", "aka, aka-prime, sim",
                "auth.eap.sim.pseudonym.keys", "k:000102030405060708090a0b0c0d0e0f"));
        AuthConfig auth = new AuthConfig(
                true, 0, 2, 256, 4096, Duration.ofSeconds(10), Duration.ofSeconds(2), Duration.ofSeconds(30));
        gateway = cluster.startGateway(
                1,
                0,
                anyPrivateNas(),
                auth,
                Gateway.storeHandler(settings, auth),
                RadsecConfig.DISABLED,
                CoaConfig.DISABLED,
                ProxyConfig.DISABLED,
                "0.0.0.0");
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        warmUp(gateway.radiusPort());
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "state version 8 activated",
                    () -> admin.state().activeVersion() >= 8);
        }
    }

    @AfterAll
    static void stop() {
        if (cluster != null) {
            cluster.close();
        }
        if (peer != null) {
            peer.stop();
        }
    }

    @Test
    void akaWithTheUsimsKeys() throws Exception {
        Container.ExecResult r = run("aka", """
                eap=AKA
                identity="0262011000000001%s"
                password="%s:%s:000000000000"
                """.formatted(REALM, KI, OPC));
        assertThat(r.getStdout()).contains("SUCCESS").contains("welcome, SIM 1");
    }

    @Test
    void akaPrimeWithAStoredOp() throws Exception {
        Container.ExecResult r = run("aka-prime", """
                eap=AKA'
                identity="6262011000000002%s"
                password="%s:%s:000000000000"
                """.formatted(REALM, KI, OPC));
        assertThat(r.getStdout()).contains("SUCCESS");
    }

    @Test
    void aUsimAheadOfTheServerIsResynchronised() throws Exception {
        Container.ExecResult r = run("resync", """
                eap=AKA
                identity="0262011000000003%s"
                password="%s:%s:000000100000"
                """.formatted(REALM, KI, OPC));
        assertThat(r.getStdout()).contains("SUCCESS");
        assertThat(r.getStdout()).as("the USIM reported its SQN").contains("Synchronization-Failure");
    }

    @Test
    void anAnonymousIdentityIsAskedForThePermanentOne() throws Exception {
        Container.ExecResult r = run("anonymous", """
                eap=AKA
                anonymous_identity="anonymous%s"
                identity="0262011000000004%s"
                password="%s:%s:000000000000"
                """.formatted(REALM, REALM, KI, OPC));
        assertThat(r.getStdout()).contains("SUCCESS");
    }

    @Test
    void aWrongKeyOrAnUnknownImsiFails() throws Exception {
        Container.ExecResult wrong = run("wrong-key", """
                eap=AKA
                identity="0262011000000005%s"
                password="00000000000000000000000000000000:%s:000000000000"
                """.formatted(REALM, OPC));
        assertThat(wrong.getStdout()).contains("FAILURE").doesNotContain("(Access-Accept)");
        Container.ExecResult unknown = run("unknown", """
                eap=AKA
                identity="0262011000000099%s"
                password="%s:%s:000000000000"
                """.formatted(REALM, KI, OPC));
        assertThat(unknown.getStdout()).contains("FAILURE").doesNotContain("(Access-Accept)");
    }

    @Test
    void simWithGsmMilenage() throws Exception {
        Container.ExecResult r = run("sim", """
                eap=SIM
                identity="1262011000000006%s"
                password="%s:%s"
                """.formatted(REALM, KI, OPC));
        assertThat(r.getStdout()).contains("SUCCESS").contains("EAP-SIM");
    }

    @Test
    void simWithStoredTripletsAndAnAnonymousIdentity() throws Exception {
        Container.ExecResult r = run("sim-triplets", """
                eap=SIM
                anonymous_identity="anonymous%s"
                identity="1262011000000007%s"
                password="%s:%s"
                """.formatted(REALM, REALM, KI, OPC));
        assertThat(r.getStdout()).contains("SUCCESS");
    }

    @Test
    void fastReauthenticationAfterAFullOneForEveryMethod() throws Exception {
        for (String[] method : new String[][] {
            {"AKA", "0262011000000001", KI + ":" + OPC + ":000000000000"},
            {"AKA'", "6262011000000002", KI + ":" + OPC + ":000000000000"},
            {"SIM", "1262011000000006", KI + ":" + OPC}
        }) {
            Container.ExecResult r = run(
                    "reauth-" + method[0].replace("'", "-prime"),
                    """
                    eap=%s
                    identity="%s%s"
                    password="%s"
                    """.formatted(method[0], method[1], REALM, method[2]),
                    2);
            assertThat(r.getStdout().split("CTRL-EVENT-EAP-SUCCESS", -1))
                    .as(method[0] + ": three authentications")
                    .hasSize(4);
            assertThat(r.getStdout())
                    .as(method[0] + ": the later ones are fast re-authentications")
                    .contains("Subtype=13")
                    .contains("AT_NEXT_PSEUDONYM")
                    .doesNotContain("mismatch: 1");
        }
    }

    /** Three triplets as an operator's AuC would have issued them: GSM-MILENAGE of the same Ki and OPc. */
    static final class StoredTriplets {
        static String items() {
            StringBuilder b = new StringBuilder();
            byte[] k = java.util.HexFormat.of().parseHex(KI);
            byte[] opc = java.util.HexFormat.of().parseHex(OPC);
            for (int i = 1; i <= 3; i++) {
                byte[] rand = new byte[16];
                rand[15] = (byte) i;
                byte[][] t = io.radiusward.gateway.SimVectors.gsm(k, opc, rand);
                b.append(i == 1 ? "" : ", ")
                        .append("EAP-Sim-Rand")
                        .append(i)
                        .append(" := 0x")
                        .append(java.util.HexFormat.of().formatHex(rand))
                        .append(", EAP-Sim-SRES")
                        .append(i)
                        .append(" := 0x")
                        .append(java.util.HexFormat.of().formatHex(t[0]))
                        .append(", EAP-Sim-KC")
                        .append(i)
                        .append(" := 0x")
                        .append(java.util.HexFormat.of().formatHex(t[1]));
            }
            return b.toString();
        }
    }

    static Container.ExecResult run(String name, String network) throws Exception {
        return run(name, network, 0);
    }

    /** @param again further authentications in the same run: fast re-authentications when the server offers them */
    static Container.ExecResult run(String name, String network, int again) throws Exception {
        String conf = "network={\n    key_mgmt=WPA-EAP\n" + network.indent(4) + "}\n";
        Path file = Files.writeString(dir.resolve(name + ".conf"), conf, StandardCharsets.UTF_8);
        peer.copyFileToContainer(MountableFile.forHostPath(file), "/work/" + name + ".conf");
        Container.ExecResult result = peer.execInContainer(
                "sh",
                "-c",
                "eapol_test -c /work/" + name + ".conf -a \"$(getent hosts host.docker.internal | cut -d' ' -f1)\""
                        + " -p " + gateway.authPort() + " -s " + SECRET + " -t 20 -r " + again);
        Path logs = Path.of("target/eapol-test-logs");
        Files.createDirectories(logs);
        Files.writeString(logs.resolve("aka-" + name + ".log"), result.getStdout() + result.getStderr());
        return result;
    }

    /** The peer's packets come from a private address: the Docker bridge, or loopback through Colima. */
    static NasRegistry anyPrivateNas() {
        byte[] secret = SECRET.getBytes(StandardCharsets.UTF_8);
        int[][] ranges = {{0x7F000000, 8}, {0x0A000000, 8}, {0xAC100000, 12}, {0xC0A80000, 16}};
        return NasRegistry.of(Arrays.stream(ranges)
                .map(r -> new NasClient(
                        "peer-" + Integer.toHexString(r[0]),
                        r[0] >>> 8,
                        r[0],
                        r[1],
                        secret,
                        "default",
                        NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                        new NasClient.Identity[0],
                        0,
                        NasClient.MessageAuthenticatorPolicy.OPTIONAL))
                .toList());
    }

    /** One Accounting-Request, so the log has a recording and members report their state versions. */
    static void warmUp(int port) throws Exception {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, 1)
                .uint32(40, 1)
                .attribute(44, "warm-up")
                .attribute(1, "nobody")
                .uint32(55, 1_780_000_000L);
        int length = enc.finish();
        new RadiusAuthenticator()
                .signAccountingRequest(buffer, 0, length, -1, SECRET.getBytes(StandardCharsets.US_ASCII));
        try (DatagramChannel nas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0))) {
            nas.configureBlocking(false);
            InetSocketAddress target = new InetSocketAddress("127.0.0.1", port);
            ByteBuffer in = ByteBuffer.allocate(4096);
            for (int attempt = 0; attempt < 8; attempt++) {
                nas.send(ByteBuffer.wrap(Arrays.copyOf(buffer.byteArray(), length)), target);
                long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
                while (System.nanoTime() < deadline) {
                    in.clear();
                    if (nas.receive(in) != null) {
                        return;
                    }
                    Thread.sleep(2);
                }
            }
        }
        throw new AssertionError("no Accounting-Response");
    }
}
