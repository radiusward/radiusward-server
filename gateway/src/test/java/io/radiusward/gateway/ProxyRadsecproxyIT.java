/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.testing.images.TestImages;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * The gateway's RadSec client against radsecproxy as the home side (ADR 0037, milestone 7): the gateway proxies a realm
 * over TLS to radsecproxy in a container ({@code testing/radsec-client}), which forwards over UDP to a fake home server
 * on the host. The Accept comes back through both: its MS-MPPE key re-encrypted by radsecproxy (home secret to
 * {@code radsec}) and by the gateway ({@code radsec} to the NAS's secret) must still be the home server's key. Skipped
 * where Docker is missing, a failure where it is required.
 */
@Epic("Proxying")
@Feature("Interop with radsecproxy")
@Link(name = "ADR 0037", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0037-proxying.md")
class ProxyRadsecproxyIT {

    @TempDir
    Path dir;

    private GenericContainer<?> radsecproxy;
    private Gateway gateway;
    private FakeHomeServer home;
    private final ProxyIT nas = new ProxyIT();

    @AfterEach
    void stop() throws Exception {
        nas.stop();
        if (gateway != null) {
            gateway.close();
        }
        if (radsecproxy != null) {
            Path logs = Path.of("target/radsec-client");
            Files.createDirectories(logs);
            Files.writeString(logs.resolve("radsecproxy-home.log"), radsecproxy.getLogs());
            radsecproxy.stop();
        }
        if (home != null) {
            home.close();
        }
    }

    @Test
    void radsecproxyRelaysTheHomeServersAnswer() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        home = new FakeHomeServer("home-secret", "0.0.0.0");
        TestPki pki = new TestPki(dir, "relay");
        TestPki.Issued client = pki.client("gateway.corp.test");
        Path clientPem = TestPki.write(
                dir.resolve("gateway.pem"), "CERTIFICATE", client.certificate().getEncoded());
        Path clientKey = TestPki.write(
                dir.resolve("gateway.key"),
                "PRIVATE KEY",
                client.keys().getPrivate().getEncoded());
        Path conf = Files.writeString(dir.resolve("radsecproxy.template"), """
                ListenTLS *:2083
                LogLevel 4
                tls default {
                    CACertificateFile /work/ca.pem
                    CertificateFile /work/server.pem
                    CertificateKeyFile /work/server.key
                }
                client gateway {
                    host 0.0.0.0/0
                    type tls
                    secret radsec
                }
                server home {
                    host HOST
                    port %d
                    type udp
                    secret home-secret
                }
                realm * {
                    server home
                }
                """.formatted(home.port()));
        radsecproxy = new GenericContainer<>(TestImages.image("radsec-client"))
                .withExtraHost("host.docker.internal", "host-gateway")
                .withCopyFileToContainer(MountableFile.forHostPath(pki.caPem), "/work/ca.pem")
                .withCopyFileToContainer(MountableFile.forHostPath(pki.serverPem), "/work/server.pem")
                .withCopyFileToContainer(MountableFile.forHostPath(pki.serverKey), "/work/server.key")
                .withCopyFileToContainer(MountableFile.forHostPath(conf), "/work/radsecproxy.template")
                .withExposedPorts(2083)
                .withCommand(
                        "sh",
                        "-c",
                        "sed \"s/HOST/$(getent hosts host.docker.internal | cut -d' ' -f1)/\""
                                + " /work/radsecproxy.template > /work/radsecproxy.conf"
                                + " && exec radsecproxy -f -c /work/radsecproxy.conf")
                .waitingFor(Wait.forListeningPorts(2083));
        radsecproxy.start();

        Path users = Files.writeString(dir.resolve("none"), "");
        Config settings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("proxy.enabled", "true"),
                Map.entry("proxy.timeout", "2s"),
                Map.entry("proxy.retries", "1"),
                Map.entry("home.relay.address", radsecproxy.getHost() + ":" + radsecproxy.getMappedPort(2083)),
                Map.entry("home.relay.transport", "tls"),
                Map.entry("home.relay.tls.certificate", clientPem.toString()),
                Map.entry("home.relay.tls.key", clientKey.toString()),
                Map.entry("home.relay.tls.ca", pki.caPem.toString()),
                Map.entry("home.relay.tls.name", "radius.relay.test"),
                Map.entry("pool.relay.servers", "relay"),
                Map.entry("realm.partner.name", "partner.example"),
                Map.entry("realm.partner.pool", "relay")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        gateway = Gateway.launchWith(
                config(),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                auth,
                Gateway.storeHandler(settings, auth),
                RadsecConfig.DISABLED,
                CoaConfig.DISABLED,
                ProxyConfig.from(settings));

        byte[] request = nas.pap("alice@partner.example", "relayed-pw", "aa-bb-cc-00-04-01");
        byte[] answer = null;
        for (int attempt = 0; attempt < 5 && answer == null; attempt++) {
            answer = nas.send(gateway.authPort(), request, Duration.ofSeconds(3));
        }
        ProxyIT.assertForTheNas(answer, request, RadiusCode.ACCESS_ACCEPT);
        assertThat(home.requests).isNotEmpty();
        assertThat(home.requests.get(0).password())
                .as("decrypted at the far end")
                .isEqualTo("relayed-pw");

        RadiusPacket r = AuthAgentTest.wrap(answer);
        int vsa = -1;
        for (int at = r.attributesOffset(); at < r.attributesEnd(); at += answer[at + 1] & 0xFF) {
            if (answer[at] == 26) {
                vsa = at;
            }
        }
        assertThat(vsa).as("MS-MPPE-Recv-Key relayed").isPositive();
        byte[] value = Arrays.copyOfRange(answer, vsa + 8, vsa + (answer[vsa + 7] & 0xFF) + 6);
        assertThat(ProxyIT.decryptKey(value, AuthAgentTest.SECRET, Arrays.copyOfRange(request, 4, 20)))
                .as("re-encrypted twice, still the home server's key")
                .isEqualTo(FakeHomeServer.MPPE_KEY);
        assertThat(new String(answer, StandardCharsets.ISO_8859_1)).contains("home says hello");
    }

    private GatewayConfig config() {
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
                new File(dir.toFile(), "aeron").getPath(),
                c.dictionaryDir(),
                c.debugResponseDelay());
    }
}
