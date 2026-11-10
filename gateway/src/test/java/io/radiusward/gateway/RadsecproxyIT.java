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
import java.util.HashMap;
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
 * radsecproxy ({@code testing/radsec-client}) as an independent RadSec and DTLS client of the real gateway (ADR 0034,
 * ADR 0038): one instance forwards over TLS, a second over DTLS 1.2 with the secret {@code radius/dtls}.
 * FreeRADIUS's {@code radclient} and wpa_supplicant's {@code eapol_test} send over UDP to radsecproxy in the container,
 * which forwards over TLS. PAP, Status-Server, and PEAP and TTLS whose MS-MPPE keys must survive both secrets (the
 * gateway encrypts them with the RadSec secret, radsecproxy re-encrypts them for its UDP client). Skipped where Docker
 * is missing, a failure where it is required.
 */
class RadsecproxyIT {

    static final String UDP_SECRET = "proxy-secret";
    /** Where the radsecproxy instance forwarding over DTLS listens for {@code radclient} and {@code eapol_test}. */
    static final int DTLS_PROXY_PORT = 1912;

    @TempDir
    static Path dir;

    static GenericContainer<?> proxy;
    static Gateway gateway;

    @BeforeAll
    static void start() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        Path image = Path.of("../testing/radsec-client").toAbsolutePath().normalize();
        proxy = new GenericContainer<>(new ImageFromDockerfile("radiusward-radsec-client:test", false)
                        .withFileFromPath("Dockerfile", image.resolve("Dockerfile")))
                .withExtraHost("host.docker.internal", "host-gateway");
        proxy.start();

        TestPki pki = new TestPki(dir, "radsec");
        TestPki.Issued client = pki.client("radsecproxy.corp.test");
        copy(pki.caPem, "ca.pem");
        copy(
                TestPki.write(
                        dir.resolve("client.pem"),
                        "CERTIFICATE",
                        client.certificate().getEncoded()),
                "client.pem");
        copy(
                TestPki.write(
                        dir.resolve("client.key"),
                        "PRIVATE KEY",
                        client.keys().getPrivate().getEncoded()),
                "client.key");

        Path users = Files.writeString(dir.resolve("users"), "alice   Cleartext-Password := \"Alice-Passw0rd!\"\n");
        NasRegistry registry = EapolTestIT.anyPrivateNas();
        Map<String, String> settings = new HashMap<>(Map.of(
                "auth.stores",
                "local",
                "auth.store.local.type",
                "file",
                "auth.store.local.path",
                users.toString(),
                "auth.store.local.mschap",
                "true",
                "auth.plugins.dir",
                dir.resolve("no-plugins").toString(),
                "auth.eap.methods",
                "peap, ttls",
                "auth.eap.tls.certificate",
                pki.serverPem.toString(),
                "auth.eap.tls.key",
                pki.serverKey.toString()));
        settings.putAll(Map.of(
                "radsec.enabled", "true",
                "radsec.port", "0",
                "radsec.dtls.enabled", "true",
                "radsec.dtls.port", "0",
                "radsec.certificate", pki.serverPem.toString(),
                "radsec.key", pki.serverKey.toString(),
                "radsec.ca", pki.caPem.toString()));
        for (NasClient nas : registry.clients()) {
            settings.put("nas." + nas.name() + ".radsec", "true");
            settings.put("nas." + nas.name() + ".radsec.identity", "radsecproxy.corp.test");
            settings.put("nas." + nas.name() + ".dtls", "true");
            settings.put("nas." + nas.name() + ".dtls.identity", "radsecproxy.corp.test");
        }
        Config config = Config.of(settings);
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        gateway = Gateway.launchWith(
                gatewayConfig(),
                registry,
                auth,
                Gateway.storeHandler(config, auth),
                RadsecConfig.from(config, "0.0.0.0"));

        Files.writeString(dir.resolve("radsecproxy.conf"), """
                ListenUDP 127.0.0.1:1812
                LogLevel 4
                tls default {
                    CACertificateFile /work/ca.pem
                    CertificateFile /work/client.pem
                    CertificateKeyFile /work/client.key
                }
                client local {
                    host 127.0.0.1
                    type udp
                    secret %s
                }
                server gateway {
                    host GATEWAY
                    port %d
                    type tls
                    secret radsec
                    CertificateNameCheck off
                    StatusServer on
                }
                realm * {
                    server gateway
                }
                """.formatted(UDP_SECRET, gateway.radsecPort()));
        Files.writeString(
                dir.resolve("radsecproxy-dtls.conf"), """
                ListenUDP 127.0.0.1:%d
                LogLevel 4
                tls default {
                    CACertificateFile /work/ca.pem
                    CertificateFile /work/client.pem
                    CertificateKeyFile /work/client.key
                }
                client local {
                    host 127.0.0.1
                    type udp
                    secret %s
                }
                server gateway {
                    host GATEWAY
                    port %d
                    type dtls
                    secret radius/dtls
                    CertificateNameCheck off
                    StatusServer on
                }
                realm * {
                    server gateway
                }
                """.formatted(DTLS_PROXY_PORT, UDP_SECRET, gateway.dtlsPort()));
        for (String instance : new String[] {"radsecproxy", "radsecproxy-dtls"}) {
            copy(dir.resolve(instance + ".conf"), instance + ".template");
            Container.ExecResult started = proxy.execInContainer(
                    "sh",
                    "-c",
                    "sed \"s/GATEWAY/$(getent hosts host.docker.internal | cut -d' ' -f1)/\" /work/" + instance
                            + ".template > /work/" + instance + ".conf && nohup radsecproxy -f -c /work/" + instance
                            + ".conf -d 4 > /work/" + instance + ".log 2>&1 &");
            assertThat(started.getExitCode()).isZero();
        }
    }

    @AfterAll
    static void stop() throws Exception {
        if (proxy != null) {
            Path logs = Path.of("target/radsec-client");
            Files.createDirectories(logs);
            for (String instance : new String[] {"radsecproxy", "radsecproxy-dtls"}) {
                proxy.copyFileFromContainer(
                        "/work/" + instance + ".log",
                        logs.resolve(instance + ".log").toString());
            }
            proxy.stop();
        }
        if (gateway != null) {
            gateway.close();
        }
    }

    @Test
    void papThroughRadsecproxy() throws Exception {
        Container.ExecResult accept = radclient("User-Name = alice, User-Password = \"Alice-Passw0rd!\"");
        assertThat(accept.getStdout()).as(accept.getStderr()).contains("Received Access-Accept");
        Container.ExecResult reject = radclient("User-Name = alice, User-Password = \"wrong\"");
        assertThat(reject.getStdout()).as(reject.getStderr()).contains("Received Access-Reject");
        assertThat(gateway.radsecAgent().get(RadsecAgent.Counter.REQUESTS)).isPositive();
        assertThat(gateway.radsecAgent().openConnections()).isEqualTo(1);
    }

    @Test
    void papThroughRadsecproxyOverDtls() throws Exception {
        Container.ExecResult accept =
                radclient("User-Name = alice, User-Password = \"Alice-Passw0rd!\"", DTLS_PROXY_PORT);
        assertThat(accept.getStdout()).as(accept.getStderr()).contains("Received Access-Accept");
        Container.ExecResult reject = radclient("User-Name = alice, User-Password = \"wrong\"", DTLS_PROXY_PORT);
        assertThat(reject.getStdout()).as(reject.getStderr()).contains("Received Access-Reject");
        RadsecAgent agent = gateway.radsecAgent();
        assertThat(agent.getDtls(RadsecAgent.Counter.REQUESTS)).isPositive();
        assertThat(agent.openAssociations()).isEqualTo(1);
        assertThat(agent.getDtls(RadsecAgent.Counter.NAS_REFUSED)).isZero();
    }

    @Test
    void peapAndTtlsThroughRadsecproxyKeepTheirKeys() throws Exception {
        peapAndTtls(1812);
    }

    @Test
    void peapAndTtlsOverDtlsKeepTheirKeys() throws Exception {
        peapAndTtls(DTLS_PROXY_PORT); // MS-MPPE keys encrypted with radius/dtls, re-encrypted by radsecproxy
    }

    private void peapAndTtls(int port) throws Exception {
        for (String network : new String[] {"""
                eap=PEAP
                identity="alice"
                anonymous_identity="anonymous"
                password="Alice-Passw0rd!"
                ca_cert="/work/ca.pem"
                phase1="peapver=0 crypto_binding=2 tls_disable_tlsv1_3=0"
                phase2="auth=MSCHAPV2"
                """, """
                eap=TTLS
                identity="alice"
                anonymous_identity="anonymous"
                password="Alice-Passw0rd!"
                ca_cert="/work/ca.pem"
                phase1="tls_disable_tlsv1_3=1"
                phase2="auth=PAP"
                """}) {
            Path conf = Files.writeString(
                    dir.resolve("eap.conf"),
                    "network={\n    key_mgmt=WPA-EAP\n" + network.indent(4) + "}\n",
                    StandardCharsets.UTF_8);
            copy(conf, "eap.conf");
            Container.ExecResult result = proxy.execInContainer(
                    "eapol_test",
                    "-c",
                    "/work/eap.conf",
                    "-a",
                    "127.0.0.1",
                    "-p",
                    Integer.toString(port),
                    "-s",
                    UDP_SECRET,
                    "-t",
                    "20");
            assertThat(result.getExitCode()).as(result.getStdout()).isZero();
            assertThat(result.getStdout()).contains("SUCCESS").contains("MPPE keys OK: 1  mismatch: 0");
        }
    }

    private static Container.ExecResult radclient(String attributes) throws Exception {
        return radclient(attributes, 1812);
    }

    private static Container.ExecResult radclient(String attributes, int port) throws Exception {
        return proxy.execInContainer(
                "sh",
                "-c",
                "echo '" + attributes + ", Message-Authenticator = 0x00' | radclient -r 5 -t 3 -x 127.0.0.1:" + port
                        + " auth " + UDP_SECRET);
    }

    private static void copy(Path file, String name) {
        proxy.copyFileToContainer(MountableFile.forHostPath(file), "/work/" + name);
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
