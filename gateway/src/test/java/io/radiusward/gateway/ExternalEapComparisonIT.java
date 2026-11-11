/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
 * The same EAP profiles against an installed external RADIUS server ({@code radiusd}, {@code -Pinterop}) and against
 * the gateway, with wpa_supplicant's {@code eapol_test} ({@code testing/eapol-test}) as the peer of both (ADR 0039):
 * each profile must end the same way on both — accepted with the MS-MPPE keys matching the peer's MSK, or rejected —
 * and where both resume, both resume. Both servers use the same users file, certificates and secret.
 *
 * <p>Profiles: PEAPv0 with MS-CHAPv2 (TLS 1.2 and 1.3) and GTC, a wrong password, a peer that lets the server choose
 * the PEAP version, a peer forced to PEAPv1 (neither server offers it: the peer gives up), TTLS with PAP and
 * MS-CHAPv2, EAP-TLS (TLS 1.2 and 1.3), each authenticated twice on one TLS session ({@code -r 1}); PEAP requiring a
 * client certificate with and without one, and EAP-SIM with stored triplets (ADR 0061). Skipped without the interop profile or an installed {@code radiusd}, and
 * where Docker is missing (a failure where it is required).
 */
@Epic("EAP")
@Feature("Interop with another RADIUS server")
@Link(
        name = "ADR 0039",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0039-peap-alignment.md")
@Link(name = "ADR 0061", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0061-eap-sim-aka.md")
class ExternalEapComparisonIT {

    static final String SECRET = "comparison-secret";
    static final Path LOGS = Path.of("target/eap-comparison");

    @TempDir
    static Path dir;

    static GenericContainer<?> peer;
    static ExternalRadiusServer external;
    static int externalPort;
    static int externalCertificatePort;
    static Gateway gateway;
    static Gateway certificateGateway;

    /** What a profile must end with on both servers. */
    enum Outcome {
        ACCEPTED,
        REJECTED
    }

    record Profile(String name, Outcome outcome, String network) {}

    @BeforeAll
    static void start() throws Exception {
        assumeTrue(Boolean.getBoolean("radiusward.interop"), "interop profile not active");
        Optional<Path> binary = ExternalRadiusServer.binary();
        assumeTrue(binary.isPresent(), "no radiusd installed");
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));

        TestPki pki = new TestPki(dir, "comparison");
        TestPki.Issued laptop = pki.client("alice");
        Path laptopPem = TestPki.write(
                dir.resolve("laptop.pem"), "CERTIFICATE", laptop.certificate().getEncoded());
        Path laptopKey = TestPki.write(
                dir.resolve("laptop.key"),
                "PRIVATE KEY",
                laptop.keys().getPrivate().getEncoded());
        Path users = Files.writeString(
                dir.resolve("users"),
                "alice   Cleartext-Password := \"Alice-Passw0rd!\"\n"
                        // EAP-SIM with stored triplets (ADR 0061): the external server looks the subscriber up by
                        // its identity with the hint, the gateway by the IMSI
                        + "1" + SIM_IMSI + "  " + storedTriplets() + "\n"
                        + SIM_IMSI + "  " + storedTriplets() + "\n");

        Path serverDir = Files.createDirectories(dir.resolve("external"));
        Path cache = Files.createDirectories(serverDir.resolve("tls-cache"));
        Files.createDirectories(cache.resolve("eap")); // the persisted sessions of each EAP instance
        Files.createDirectories(cache.resolve("eap_certificate"));
        externalPort = ExternalRadiusServer.freeUdpPort();
        externalCertificatePort = ExternalRadiusServer.freeUdpPort();
        external = ExternalRadiusServer.start(binary.get(), serverDir, externalConfig(pki, users, cache));

        Map<String, String> settings = new java.util.HashMap<>(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.store.local.mschap", "true"),
                Map.entry("auth.store.local.chap", "true"),
                Map.entry("auth.plugins.dir", dir.resolve("no-plugins").toString()),
                Map.entry("auth.eap.methods", "peap, ttls, tls, teap, pwd, sim"),
                Map.entry("auth.eap.peap.inner", "mschapv2, gtc"),
                Map.entry("auth.eap.tls.certificate", pki.serverPem.toString()),
                Map.entry("auth.eap.tls.key", pki.serverKey.toString()),
                Map.entry("auth.eap.tls.ca", pki.caPem.toString()),
                Map.entry("auth.eap.tls.identity", "any")));
        gateway = launch(settings, "default");
        settings.put("auth.eap.peap.client.certificate", "true");
        certificateGateway = launch(settings, "certificate");

        Path image = Path.of("../testing/eapol-test").toAbsolutePath().normalize();
        peer = new GenericContainer<>(new ImageFromDockerfile("radiusward-eapol-test:test", false)
                        .withFileFromPath("Dockerfile", image.resolve("Dockerfile")))
                .withExtraHost("host.docker.internal", "host-gateway");
        peer.start();
        copy(pki.caPem, "ca.pem");
        copy(laptopPem, "laptop.pem");
        copy(laptopKey, "laptop.key");
    }

    private static Gateway launch(Map<String, String> settings, String name) {
        Config config = Config.of(settings);
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        return Gateway.launchWith(gatewayConfig(name), nas(), auth, Gateway.storeHandler(config, auth));
    }

    /**
     * EAP-TLS, PEAP (MS-CHAPv2 and GTC inside) and TTLS with a persistent session cache, so that it resumes; a second
     * EAP instance that requires client certificates for PEAP, on its own port.
     */
    private static String externalConfig(TestPki pki, Path users, Path cache) {
        String eap = """
                    eap %1$s {
                        default_eap_type = peap
                        timer_expire = 60
                        max_sessions = 1024
                        tls-config tls-%1$s {
                            private_key_file = %2$s
                            certificate_file = %3$s
                            ca_file = %4$s
                            tls_min_version = "1.2"
                            tls_max_version = "1.3"
                            cipher_list = "DEFAULT"
                            fragment_size = 1024
                            cache {
                                enable = yes
                                lifetime = 1
                                name = "%1$s"
                                persist_dir = "%5$s"
                            }
                        }
                        tls {
                            tls = tls-%1$s
                        }
                        peap {
                            tls = tls-%1$s
                            default_eap_type = mschapv2
                            virtual_server = inner-tunnel
                            %6$s
                        }
                        ttls {
                            tls = tls-%1$s
                            default_eap_type = mschapv2
                            virtual_server = inner-tunnel
                        }
                        pwd {
                            group = 19
                            server_id = external
                            virtual_server = inner-tunnel
                        }
                        teap {
                            tls = tls-%1$s
                            authority_identity = "external"
                            # required by 3.2.5 (Ubuntu, CI), optional in 3.2.10; a test-only key
                            pac_opaque_key = "0123456789abcdef0123456789ABCDEF"
                            default_eap_type = mschapv2
                            virtual_server = inner-tunnel
                        }
                        mschapv2 {
                        }
                        sim {
                        }
                        md5 {
                        }
                        gtc {
                            auth_type = PAP
                        }
                    }
                """;
        String outer = """
                server %1$s {
                    listen {
                        type = auth
                        ipaddr = *
                        port = %2$d
                    }
                    authorize {
                        %3$s {
                            ok = return
                        }
                        files
                        pap
                    }
                    authenticate {
                        Auth-Type PAP {
                            pap
                        }
                        %3$s
                    }
                }
                """;
        return "modules {\n    pap {\n    }\n    chap {\n    }\n    mschap {\n    }\n    files {\n        filename = "
                + users
                + "\n    }\n"
                + eap.formatted("eap", pki.serverKey, pki.serverPem, pki.caPem, cache.resolve("eap"), "")
                + eap.formatted(
                        "eap_certificate",
                        pki.serverKey,
                        pki.serverPem,
                        pki.caPem,
                        cache.resolve("eap_certificate"),
                        "require_client_cert = yes")
                + "}\n"
                + """
                client any {
                    ipaddr = 0.0.0.0/0
                    secret = %s
                }
                """.formatted(SECRET)
                + outer.formatted("default", externalPort, "eap")
                + outer.formatted("certificate", externalCertificatePort, "eap_certificate")
                + """
                server inner-tunnel {
                    authorize {
                        chap
                        mschap
                        eap {
                            ok = return
                        }
                        files
                        pap
                    }
                    authenticate {
                        Auth-Type PAP {
                            pap
                        }
                        Auth-Type CHAP {
                            chap
                        }
                        Auth-Type MS-CHAP {
                            mschap
                        }
                        eap
                    }
                }
                """;
    }

    @AfterAll
    static void stop() throws Exception {
        if (peer != null) {
            peer.stop();
        }
        for (Gateway g : new Gateway[] {gateway, certificateGateway}) {
            if (g != null) {
                g.close();
            }
        }
        if (external != null) {
            external.stop("eap-comparison");
        }
    }

    static final String TLS12 = "tls_disable_tlsv1_3=1";
    static final String TLS13 = "tls_disable_tlsv1_3=0 tls_disable_tlsv1_2=1";

    static String peap(String phase1, String phase2, String password) {
        return """
                eap=PEAP
                identity="alice"
                anonymous_identity="anonymous"
                password="%s"
                ca_cert="/work/ca.pem"
                phase1="%s"
                phase2="%s"
                """.formatted(password, phase1, phase2);
    }

    static String ttls(String phase2, String password) {
        return """
                eap=TTLS
                identity="alice"
                anonymous_identity="anonymous"
                password="%s"
                ca_cert="/work/ca.pem"
                phase1="%s"
                phase2="%s"
                """.formatted(password, TLS12, phase2);
    }

    static String pwd(String password) {
        return """
                eap=PWD
                identity="alice"
                password="%s"
                """.formatted(password);
    }

    static String teap(String phase2, String password) {
        return """
                eap=TEAP
                identity="alice"
                anonymous_identity="anonymous"
                password="%s"
                ca_cert="/work/ca.pem"
                phase1="%s"
                phase2="%s"
                """.formatted(password, TLS12, phase2);
    }

    static final String SIM_IMSI = "262011000000007";

    /** Three triplets for fixed RANDs, as an AuC would have issued them: GSM-MILENAGE of 3GPP test set 1's keys. */
    static String storedTriplets() {
        Milenage m = new Milenage(EapAkaTest.KI, EapAkaTest.OPC);
        StringBuilder b = new StringBuilder();
        for (int i = 1; i <= 3; i++) {
            byte[] rand = new byte[16];
            rand[15] = (byte) i;
            Milenage.Triplet t = m.gsm(rand);
            java.util.HexFormat hex = java.util.HexFormat.of();
            b.append(i == 1 ? "" : ", ")
                    .append("EAP-Sim-Rand")
                    .append(i)
                    .append(" := 0x")
                    .append(hex.formatHex(rand))
                    .append(", EAP-Sim-SRES")
                    .append(i)
                    .append(" := 0x")
                    .append(hex.formatHex(t.sres()))
                    .append(", EAP-Sim-KC")
                    .append(i)
                    .append(" := 0x")
                    .append(hex.formatHex(t.kc()));
        }
        return b.toString();
    }

    static String sim(String ki) {
        return """
                eap=SIM
                identity="1%s"
                password="%s:cd63cb71954a9f4e48a5994e37a02baf"
                """.formatted(SIM_IMSI, ki);
    }

    static String tls(String phase1) {
        return """
                eap=TLS
                identity="alice"
                ca_cert="/work/ca.pem"
                client_cert="/work/laptop.pem"
                private_key="/work/laptop.key"
                phase1="%s"
                """.formatted(phase1);
    }

    static final String CLIENT_CERTIFICATE = """
            client_cert="/work/laptop.pem"
            private_key="/work/laptop.key"
            """;

    @Test
    void bothServersEndEveryProfileTheSameWay() throws Exception {
        List<Profile> profiles = List.of(
                new Profile(
                        "peap-mschapv2-tls12",
                        Outcome.ACCEPTED,
                        peap("peapver=0 " + TLS12, "auth=MSCHAPV2", "Alice-Passw0rd!")),
                new Profile(
                        "peap-mschapv2-tls13",
                        Outcome.ACCEPTED,
                        peap("peapver=0 " + TLS13, "auth=MSCHAPV2", "Alice-Passw0rd!")),
                new Profile("peap-gtc", Outcome.ACCEPTED, peap("peapver=0 " + TLS12, "auth=GTC", "Alice-Passw0rd!")),
                new Profile("peap-any-version", Outcome.ACCEPTED, peap(TLS12, "auth=MSCHAPV2", "Alice-Passw0rd!")),
                new Profile("peap-wrong-password", Outcome.REJECTED, peap(TLS12, "auth=MSCHAPV2", "wrong")),
                new Profile(
                        "peap-forced-v1",
                        Outcome.REJECTED,
                        peap("peapver=1 " + TLS12, "auth=MSCHAPV2", "Alice-Passw0rd!")),
                new Profile("ttls-pap", Outcome.ACCEPTED, ttls("auth=PAP", "Alice-Passw0rd!")),
                new Profile("ttls-mschapv2", Outcome.ACCEPTED, ttls("auth=MSCHAPV2", "Alice-Passw0rd!")),
                new Profile("ttls-wrong-password", Outcome.REJECTED, ttls("auth=PAP", "wrong")),
                new Profile("ttls-chap", Outcome.ACCEPTED, ttls("auth=CHAP", "Alice-Passw0rd!")),
                new Profile("ttls-mschap", Outcome.ACCEPTED, ttls("auth=MSCHAP", "Alice-Passw0rd!")),
                new Profile("ttls-eap-mschapv2", Outcome.ACCEPTED, ttls("autheap=MSCHAPV2", "Alice-Passw0rd!")),
                new Profile("ttls-eap-md5", Outcome.ACCEPTED, ttls("autheap=MD5", "Alice-Passw0rd!")),
                new Profile("ttls-eap-gtc", Outcome.ACCEPTED, ttls("autheap=GTC", "Alice-Passw0rd!")),
                new Profile("ttls-chap-wrong", Outcome.REJECTED, ttls("auth=CHAP", "wrong")),
                new Profile("teap-mschapv2", Outcome.ACCEPTED, teap("auth=MSCHAPV2", "Alice-Passw0rd!")),
                new Profile("pwd", Outcome.ACCEPTED, pwd("Alice-Passw0rd!")),
                new Profile("pwd-wrong", Outcome.REJECTED, pwd("wrong")),
                new Profile("teap-mschapv2-wrong", Outcome.REJECTED, teap("auth=MSCHAPV2", "wrong")),
                new Profile("ttls-eap-md5-wrong", Outcome.REJECTED, ttls("autheap=MD5", "wrong")),
                new Profile("tls-tls12", Outcome.ACCEPTED, tls(TLS12)),
                new Profile("tls-tls13", Outcome.ACCEPTED, tls(TLS13)),
                new Profile("sim-stored-triplets", Outcome.ACCEPTED, sim("465b5ce8b199b49faa5f0a2ee238a6bc")),
                new Profile("sim-wrong-key", Outcome.REJECTED, sim("00000000000000000000000000000000")));
        List<String> differences = new ArrayList<>();
        for (Profile p : profiles) {
            Container.ExecResult theirs = run("external-" + p.name(), p.network(), externalPort);
            Container.ExecResult ours = run("gateway-" + p.name(), p.network(), gateway.authPort());
            check(p, "external", theirs, differences);
            check(p, "gateway", ours, differences);
            if (p.outcome() == Outcome.ACCEPTED && resumed(theirs) != resumed(ours)) {
                differences.add(p.name() + ": the external server " + (resumed(theirs) ? "resumed" : "did not resume")
                        + ", the gateway " + (resumed(ours) ? "resumed" : "did not"));
            }
            if (p.name().startsWith("peap-mschapv2") && innerChallenges(theirs) != innerChallenges(ours)) {
                differences.add(p.name() + ": inner MS-CHAPv2 challenges " + innerChallenges(theirs) + " vs "
                        + innerChallenges(ours) + " (fast reconnect)");
            }
        }
        assertThat(differences).as("see " + LOGS).isEmpty();
    }

    @Test
    void bothServersMayRequireAClientCertificateForPeap() throws Exception {
        String withCertificate = peap("peapver=0 " + TLS12, "auth=MSCHAPV2", "Alice-Passw0rd!") + CLIENT_CERTIFICATE;
        String without = peap("peapver=0 " + TLS12, "auth=MSCHAPV2", "Alice-Passw0rd!");
        List<String> differences = new ArrayList<>();
        for (Profile p : List.of(
                new Profile("peap-certificate", Outcome.ACCEPTED, withCertificate),
                new Profile("peap-no-certificate", Outcome.REJECTED, without))) {
            check(p, "external", run("external-" + p.name(), p.network(), externalCertificatePort), differences);
            check(p, "gateway", run("gateway-" + p.name(), p.network(), certificateGateway.authPort()), differences);
        }
        assertThat(differences).as("see " + LOGS).isEmpty();
    }

    private static void check(Profile p, String server, Container.ExecResult result, List<String> differences) {
        String out = result.getStdout();
        boolean accepted = result.getExitCode() == 0
                && out.contains("SUCCESS")
                && !out.contains("mismatch: 1")
                && !out.contains("mismatch: 2");
        if (accepted != (p.outcome() == Outcome.ACCEPTED)) {
            differences.add(p.name() + ": " + server + " " + (accepted ? "accepted" : "did not accept") + ", expected "
                    + p.outcome());
        }
    }

    private static boolean resumed(Container.ExecResult result) {
        return result.getStdout().contains("Handshake finished - resumed=1");
    }

    private static int innerChallenges(Container.ExecResult result) {
        return result.getStdout().split("EAP-MSCHAPV2: Received challenge", -1).length - 1;
    }

    /** Two authentications on one TLS session ({@code -r 1}), fragments of 400 bytes from the peer. */
    private static Container.ExecResult run(String name, String network, int port) throws Exception {
        String conf = "network={\n    key_mgmt=WPA-EAP\n    fragment_size=400\n" + network.indent(4) + "}\n";
        Path file = Files.writeString(dir.resolve(name + ".conf"), conf, StandardCharsets.UTF_8);
        copy(file, name + ".conf");
        Container.ExecResult result = peer.execInContainer(
                "sh",
                "-c",
                "eapol_test -c /work/" + name + ".conf -a \"$(getent hosts host.docker.internal | cut -d' ' -f1)\""
                        + " -p " + port + " -s " + SECRET + " -t 20 -r 1");
        Files.createDirectories(LOGS);
        Files.writeString(LOGS.resolve(name + ".log"), result.getStdout() + result.getStderr());
        return result;
    }

    private static void copy(Path file, String name) {
        peer.copyFileToContainer(MountableFile.forHostPath(file), "/work/" + name);
    }

    /** The peer's packets come from a private address: the Docker bridge, or loopback through Colima. */
    private static NasRegistry nas() {
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

    private static GatewayConfig gatewayConfig(String name) {
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
                new File(dir.toFile(), "aeron-" + name).getPath(),
                c.dictionaryDir(),
                c.debugResponseDelay());
    }
}
