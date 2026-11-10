/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
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
 * wpa_supplicant's {@code eapol_test} ({@code testing/eapol-test}) as an independent peer against the real gateway:
 * EAP-TLS, PEAP and TTLS over TLS 1.2 and 1.3, fragments both ways, wrong credentials, MPPE keys compared with the
 * peer's MSK. Skipped where Docker is missing, a failure where it is required.
 */
class EapolTestIT {

    static final String SECRET = "eapol-secret";
    /** Each run's {@code eapol_test} output, for a failure on CI. */
    static final Path LOGS = Path.of("target/eapol-test");

    @TempDir
    static Path dir;

    static GenericContainer<?> peer;
    static Gateway gateway;
    static TestPki pki;

    @BeforeAll
    static void start() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        Path image = Path.of("../testing/eapol-test").toAbsolutePath().normalize();
        peer = new GenericContainer<>(new ImageFromDockerfile("radiusward-eapol-test:test", false)
                        .withFileFromPath("Dockerfile", image.resolve("Dockerfile")))
                .withExtraHost("host.docker.internal", "host-gateway");
        peer.start();

        pki = new TestPki(dir, "eapol");
        copy(pki.caPem, "ca.pem");
        TestPki.Issued laptop = pki.client("laptop-1");
        copy(
                TestPki.write(
                        dir.resolve("laptop.pem"),
                        "CERTIFICATE",
                        laptop.certificate().getEncoded()),
                "laptop.pem");
        copy(
                TestPki.write(
                        dir.resolve("laptop.key"),
                        "PRIVATE KEY",
                        laptop.keys().getPrivate().getEncoded()),
                "laptop.key");
        TestPki stranger = new TestPki(dir, "stranger");
        TestPki.Issued foreign = stranger.client("laptop-1");
        copy(
                TestPki.write(
                        dir.resolve("foreign.pem"),
                        "CERTIFICATE",
                        foreign.certificate().getEncoded()),
                "foreign.pem");
        copy(
                TestPki.write(
                        dir.resolve("foreign.key"),
                        "PRIVATE KEY",
                        foreign.keys().getPrivate().getEncoded()),
                "foreign.key");

        Path users = Files.writeString(dir.resolve("users"), """
                alice   Cleartext-Password := "Alice-Passw0rd!"
                carol   Cleartext-Password := "Carol-Passw0rd!", Auth-Type := Reject
                bob     NT-Password := "98c5d23f757cf4e1f9bdcd2582adb9cd"
                """);
        Config settings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.store.local.mschap", "true"),
                Map.entry("auth.store.local.chap", "true"),
                Map.entry("auth.plugins.dir", dir.resolve("no-plugins").toString()),
                Map.entry("auth.eap.methods", "peap, ttls, tls, teap, pwd"),
                Map.entry("auth.eap.peap.inner", "mschapv2, gtc, tls"),
                Map.entry("auth.eap.tls.certificate", pki.serverPem.toString()),
                Map.entry("auth.eap.tls.key", pki.serverKey.toString()),
                Map.entry("auth.eap.tls.ca", pki.caPem.toString()),
                Map.entry("auth.eap.tls.fragment.size", "400")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        gateway = Gateway.launchWith(gatewayConfig(), anyPrivateNas(), auth, Gateway.storeHandler(settings, auth));
    }

    @AfterAll
    static void stop() throws Exception {
        if (gateway != null) {
            gateway.close();
        }
        if (peer != null) {
            peer.stop();
        }
    }

    @Test
    void eapTls() throws Exception {
        for (String tls : List.of(TLS12, TLS13)) {
            assertAccepted(run("tls-" + tls.length(), """
                    eap=TLS
                    identity="laptop-1"
                    ca_cert="/work/ca.pem"
                    client_cert="/work/laptop.pem"
                    private_key="/work/laptop.key"
                    phase1="%s"
                    """.formatted(tls)));
        }
        assertRejected(run("tls-other-identity", """
                eap=TLS
                identity="laptop-2"
                ca_cert="/work/ca.pem"
                client_cert="/work/laptop.pem"
                private_key="/work/laptop.key"
                phase1="tls_disable_tlsv1_3=1"
                """));
        assertRejected(run("tls-foreign", """
                eap=TLS
                identity="laptop-1"
                ca_cert="/work/ca.pem"
                client_cert="/work/foreign.pem"
                private_key="/work/foreign.key"
                phase1="tls_disable_tlsv1_3=1"
                """));
    }

    @Test
    void peapWithMsChapV2() throws Exception {
        for (String tls : List.of(TLS12, TLS13)) {
            assertAccepted(run("peap-" + tls.length(), peap(tls, "auth=MSCHAPV2", "alice", "Alice-Passw0rd!")));
        }
        assertAccepted(run(
                "peap-unbound",
                peap(TLS12, "auth=MSCHAPV2", "alice", "Alice-Passw0rd!")
                        .replace("crypto_binding=2", "crypto_binding=0")));
        assertRejected(run("peap-wrong", peap(TLS12, "auth=MSCHAPV2", "alice", "wrong")));
        assertRejected(run("peap-carol", peap(TLS12, "auth=MSCHAPV2", "carol", "Carol-Passw0rd!")));
    }

    @Test
    void peapWithGtcAndInnerTls() throws Exception {
        assertAccepted(run("peap-gtc", peap(TLS12, "auth=GTC", "alice", "Alice-Passw0rd!")));
        assertRejected(run("peap-gtc-wrong", peap(TLS12, "auth=GTC", "alice", "wrong")));
        assertAccepted(run("peap-tls", peap(TLS12, "auth=TLS", "laptop-1", "") + """
                ca_cert2="/work/ca.pem"
                client_cert2="/work/laptop.pem"
                private_key2="/work/laptop.key"
                """));
    }

    /** {@code eapol_test -r 1}: a second authentication offers the first one's TLS session (ADR 0035). */
    @Test
    void resumption() throws Exception {
        String laptop = """
                eap=TLS
                identity="laptop-1"
                ca_cert="/work/ca.pem"
                client_cert="/work/laptop.pem"
                private_key="/work/laptop.key"
                phase1="%s"
                """;
        for (String tls : List.of(TLS12, TLS13)) {
            assertResumed(run("resume-tls-" + tls.length(), laptop.formatted(tls), 1));
            Container.ExecResult peap =
                    run("resume-peap-" + tls.length(), peap(tls, "auth=MSCHAPV2", "alice", "Alice-Passw0rd!"), 1);
            assertResumed(peap);
            assertThat(peap.getStdout())
                    .as("fast reconnect: one inner MS-CHAPv2 for two authentications")
                    .containsOnlyOnce("EAP-MSCHAPV2: Received challenge");
            assertResumed(run("resume-ttls-" + tls.length(), ttls(tls, "auth=PAP", "Alice-Passw0rd!"), 1));
        }
    }

    static void assertResumed(Container.ExecResult result) {
        assertThat(result.getExitCode()).as(result.getStdout()).isZero();
        assertThat(result.getStdout())
                .contains("MPPE keys OK: 2  mismatch: 0")
                .contains("Handshake finished - resumed=1");
    }

    @Test
    void ttls() throws Exception {
        for (String tls : List.of(TLS12, TLS13)) {
            assertAccepted(run("ttls-pap-" + tls.length(), ttls(tls, "auth=PAP", "Alice-Passw0rd!")));
            assertAccepted(run("ttls-mschapv2-" + tls.length(), ttls(tls, "auth=MSCHAPV2", "Alice-Passw0rd!")));
        }
        assertRejected(run("ttls-wrong", ttls(TLS12, "auth=PAP", "wrong")));
    }

    /** TTLS with CHAP, MS-CHAPv1 and EAP inside (ADR 0040), over TLS 1.2 and 1.3: the challenges from the tunnel. */
    @Test
    void ttlsInnerMethods() throws Exception {
        for (String tls : List.of(TLS12, TLS13)) {
            for (String phase2 :
                    List.of("auth=CHAP", "auth=MSCHAP", "autheap=MSCHAPV2", "autheap=MD5", "autheap=GTC")) {
                String name =
                        "ttls-" + phase2.replace('=', '-').toLowerCase(java.util.Locale.ROOT) + "-" + tls.length();
                assertAccepted(run(name, ttls(tls, phase2, "Alice-Passw0rd!")));
            }
        }
        for (String phase2 : List.of("auth=CHAP", "auth=MSCHAP", "autheap=MSCHAPV2", "autheap=MD5", "autheap=GTC")) {
            String name = "ttls-wrong-" + phase2.replace('=', '-').toLowerCase(java.util.Locale.ROOT);
            assertRejected(run(name, ttls(TLS12, phase2, "wrong")));
        }
    }

    /** TEAP (ADR 0041) with inner EAP methods, over TLS 1.2 and 1.3; wrong passwords; two authentications in a row. */
    @Test
    void teap() throws Exception {
        for (String tls : List.of(TLS12, TLS13)) {
            for (String phase2 : List.of("auth=MSCHAPV2", "auth=GTC", "auth=MD5")) {
                String name = "teap-" + phase2.substring(5).toLowerCase(java.util.Locale.ROOT) + "-" + tls.length();
                assertAccepted(run(name, teap(tls, phase2, "Alice-Passw0rd!")));
            }
        }
        for (String phase2 : List.of("auth=MSCHAPV2", "auth=GTC", "auth=MD5")) {
            assertRejected(run(
                    "teap-wrong-" + phase2.substring(5).toLowerCase(java.util.Locale.ROOT),
                    teap(TLS12, phase2, "wrong")));
        }
        Container.ExecResult again = run("teap-twice", teap(TLS12, "auth=MSCHAPV2", "Alice-Passw0rd!"), 1);
        assertThat(again.getStdout())
                .as("two authentications in a row; the peer offers no resumption for TEAP")
                .contains("MPPE keys OK: 2  mismatch: 0");
    }

    /**
     * EAP-pwd (ADR 0042): no certificates; alice's cleartext (preparation none), bob's NT hash (preparation MS); wrong
     * passwords rejected.
     */
    @Test
    void pwd() throws Exception {
        assertAccepted(run("pwd-cleartext", pwd("alice", "Alice-Passw0rd!")));
        assertAccepted(run("pwd-nt-hash", pwd("bob", "Bob-Passw0rd!")));
        assertRejected(run("pwd-wrong", pwd("alice", "wrong")));
        assertRejected(run("pwd-nt-hash-wrong", pwd("bob", "wrong")));
    }

    static String pwd(String user, String password) {
        return """
                eap=PWD
                identity="%s"
                password="%s"
                """.formatted(user, password);
    }

    /** A second gateway offering only TEAP with these settings. */
    private static Gateway teapGateway(String name, Map<String, String> extra) throws Exception {
        Path users =
                Files.writeString(dir.resolve(name + "-users"), "alice   Cleartext-Password := \"Alice-Passw0rd!\"\n");
        Map<String, String> settings = new java.util.HashMap<>(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.store.local.mschap", "true"),
                Map.entry("auth.plugins.dir", dir.resolve("no-plugins").toString()),
                Map.entry("auth.eap.methods", "teap"),
                Map.entry("auth.eap.tls.certificate", pki.serverPem.toString()),
                Map.entry("auth.eap.tls.key", pki.serverKey.toString()),
                Map.entry("auth.eap.tls.ca", pki.caPem.toString()),
                Map.entry("auth.eap.tls.fragment.size", "400")));
        settings.putAll(extra);
        Config config = Config.of(settings);
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        GatewayConfig c = gatewayConfig();
        GatewayConfig second = new GatewayConfig(
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
                c.aeronDir() + "-" + name,
                c.dictionaryDir(),
                c.debugResponseDelay());
        return Gateway.launchWith(second, anyPrivateNas(), auth, Gateway.storeHandler(config, auth));
    }

    /** TEAP's Basic-Password-Auth (no inner EAP) from a gateway that offers it first; checked like PAP. */
    @Test
    void teapBasicPasswordAuth() throws Exception {
        try (Gateway basic = teapGateway("basic", Map.of("auth.eap.teap.inner", "basic, mschapv2"))) {
            for (String tls : List.of(TLS12, TLS13)) {
                Container.ExecResult ok = run(
                        "teap-basic-" + tls.length(),
                        teap(tls, "auth=MSCHAPV2", "Alice-Passw0rd!"),
                        0,
                        basic.authPort());
                assertAccepted(ok);
                assertThat(ok.getStdout()).contains("Basic-Password-Auth");
            }
            assertRejected(run("teap-basic-wrong", teap(TLS12, "auth=MSCHAPV2", "wrong"), 0, basic.authPort()));
        }
    }

    /**
     * TEAP chaining (Identity-Type, ADR 0041): the machine with EAP-TLS and its certificate, then the user with
     * EAP-MSCHAPv2, in one tunnel; keys chained through both. A wrong user password fails the whole.
     */
    @Test
    void teapMachineThenUser() throws Exception {
        String machine = """
                machine_identity="host/laptop-1"
                machine_ca_cert="/work/ca.pem"
                machine_client_cert="/work/laptop.pem"
                machine_private_key="/work/laptop.key"
                machine_phase2="auth=TLS"
                """;
        try (Gateway chained = teapGateway(
                "chained", Map.of("auth.eap.teap.identity", "machine, user", "auth.eap.teap.inner", "tls, mschapv2"))) {
            for (String tls : List.of(TLS12, TLS13)) {
                Container.ExecResult ok = run(
                        "teap-machine-user-" + tls.length(),
                        teap(tls, "auth=MSCHAPV2", "Alice-Passw0rd!") + machine,
                        0,
                        chained.authPort());
                assertAccepted(ok);
                assertThat(ok.getStdout()).contains("Identity-Type");
            }
            assertRejected(run(
                    "teap-machine-user-wrong", teap(TLS12, "auth=MSCHAPV2", "wrong") + machine, 0, chained.authPort()));
        }
    }

    static String teap(String tls, String phase2, String password) {
        return """
                eap=TEAP
                identity="alice"
                anonymous_identity="anonymous"
                password="%s"
                ca_cert="/work/ca.pem"
                phase1="%s"
                phase2="%s"
                """.formatted(password, tls, phase2);
    }

    static final String TLS12 = "tls_disable_tlsv1_3=1";
    static final String TLS13 = "tls_disable_tlsv1_3=0 tls_disable_tlsv1_2=1";

    static String peap(String tls, String phase2, String user, String password) {
        return """
                eap=PEAP
                identity="%s"
                anonymous_identity="anonymous"
                password="%s"
                ca_cert="/work/ca.pem"
                phase1="peapver=0 crypto_binding=2 %s"
                phase2="%s"
                """.formatted(user, password, tls, phase2);
    }

    static String ttls(String tls, String phase2, String password) {
        return """
                eap=TTLS
                identity="alice"
                anonymous_identity="anonymous"
                password="%s"
                ca_cert="/work/ca.pem"
                phase1="%s"
                phase2="%s"
                """.formatted(password, tls, phase2);
    }

    static void assertAccepted(Container.ExecResult result) {
        assertThat(result.getExitCode()).as(result.getStdout()).isZero();
        assertThat(result.getStdout()).contains("SUCCESS").contains("MPPE keys OK: 1  mismatch: 0");
    }

    static void assertRejected(Container.ExecResult result) {
        assertThat(result.getExitCode()).as(result.getStdout()).isNotZero();
        // a Reject, or the peer gives up on a failure Result TLV without crypto-binding before it would come
        assertThat(result.getStdout()).contains("FAILURE").doesNotContain("(Access-Accept)");
    }

    /** One {@code eapol_test} run with this network block; fragments of 400 bytes from the peer, too. */
    static Container.ExecResult run(String name, String network) throws Exception {
        return run(name, network, 0);
    }

    /** @param reauthentications further authentications on the same TLS session (resumption, ADR 0035) */
    static Container.ExecResult run(String name, String network, int reauthentications) throws Exception {
        return run(name, network, reauthentications, gateway.authPort());
    }

    static Container.ExecResult run(String name, String network, int reauthentications, int port) throws Exception {
        String conf = "network={\n    key_mgmt=WPA-EAP\n    fragment_size=400\n" + network.indent(4) + "}\n";
        Path file = Files.writeString(dir.resolve(name + ".conf"), conf, StandardCharsets.UTF_8);
        copy(file, name + ".conf");
        Container.ExecResult result = peer.execInContainer(
                "sh",
                "-c",
                "eapol_test -c /work/" + name + ".conf -a \"$(getent hosts host.docker.internal | cut -d' ' -f1)\""
                        + " -p " + port + " -s " + SECRET + " -t 20 -r " + reauthentications);
        Files.createDirectories(LOGS);
        Files.writeString(LOGS.resolve(name + ".log"), result.getStdout() + result.getStderr());
        return result;
    }

    static void copy(Path file, String name) {
        peer.copyFileToContainer(MountableFile.forHostPath(file), "/work/" + name);
    }

    /** The peer's packets come from a private address: the Docker bridge, or loopback through Colima. */
    static NasRegistry anyPrivateNas() {
        byte[] secret = SECRET.getBytes(StandardCharsets.UTF_8);
        int[][] ranges = {{0x7F000000, 8}, {0x0A000000, 8}, {0xAC100000, 12}, {0xC0A80000, 16}};
        return NasRegistry.of(java.util.Arrays.stream(ranges)
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

    static GatewayConfig gatewayConfig() {
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        return new GatewayConfig(
                c.gatewayId(),
                "0.0.0.0",
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
                c.debugResponseDelay());
    }
}
