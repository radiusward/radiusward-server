/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import io.radiusward.testing.images.TestImages;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;

/**
 * A Samba AD domain controller for tests ({@code testing/samba-ad}): domain CORP.TEST, users alice (VPN Users, Staff;
 * through VPN Users also Remote Workers), bob (Staff), carol (disabled), service account svc-radius. Skipped where
 * Docker is missing, a failure where it is required.
 */
public final class SambaAd {

    static final String BASE = "DC=corp,DC=test";
    static final String SERVICE = "CN=svc-radius,CN=Users," + BASE;
    static final String SERVICE_PASSWORD = "Svc-Passw0rd!";

    private static GenericContainer<?> container;

    private SambaAd() {}

    public static synchronized GenericContainer<?> start() {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        if (container == null) {
            GenericContainer<?> c = new GenericContainer<>(TestImages.image("samba-ad"))
                    .withEnv("SAMBA_DEBUG", System.getProperty("samba.debug", "1"))
                    .withPrivilegedMode(true) // Samba keeps ACLs in extended attributes
                    .withExposedPorts(389, 636, 135, 49152, 49153, 49154, 49155)
                    .waitingFor(new WaitAllStrategy()
                            .withStrategy(Wait.forLogMessage(".*TLS self-signed keys generated OK.*", 1))
                            .withStrategy(Wait.forListeningPorts(389, 636, 135))
                            .withStartupTimeout(Duration.ofMinutes(3)));
            c.start();
            container = c;
        }
        return container;
    }

    public static final String MACHINE_ACCOUNT = "RADIUSWARD$";
    static final String MACHINE = "RADIUSWARD";
    public static final String MACHINE_PASSWORD = "Machine-Passw0rd-1234567890";

    /** Netlogon's port as the host reaches it (the endpoint mapper names the port inside the container). */
    public static int netlogonPort() throws Exception {
        int inside =
                EndpointMapper.port(endpointMapper(), NetlogonClient.NETLOGON, 1, 0, java.time.Duration.ofSeconds(5));
        return mapped(inside).getPort();
    }

    /** The endpoint mapper as the host reaches it. */
    public static java.net.InetSocketAddress endpointMapper() {
        return new java.net.InetSocketAddress(container.getHost(), container.getMappedPort(135));
    }

    /** A port inside the container (what the endpoint mapper names) as the host reaches it. */
    static java.net.InetSocketAddress mapped(int port) {
        return new java.net.InetSocketAddress(container.getHost(), container.getMappedPort(port));
    }

    /** The domain controller's log (with {@code -Dsamba.debug=10} detailed enough to see why it refuses). */
    static String logs() {
        return container.getLogs();
    }

    /** Freezes the domain controller (it accepts nothing, answers nothing) until {@link #unpause()}. */
    static void pause() {
        DockerClientFactory.instance()
                .client()
                .pauseContainerCmd(container.getContainerId())
                .exec();
    }

    static void unpause() {
        DockerClientFactory.instance()
                .client()
                .unpauseContainerCmd(container.getContainerId())
                .exec();
    }

    static String ldapUrl() {
        return "ldap://" + container.getHost() + ":" + container.getMappedPort(389);
    }

    public static String ldapsUrl() {
        return "ldaps://" + container.getHost() + ":" + container.getMappedPort(636);
    }

    /** The CA that signed the domain controller's certificate, copied out of the container. */
    public static Path ca(Path dir) throws Exception {
        Path file = dir.resolve("ca.pem");
        if (!Files.exists(file)) {
            container.copyFileFromContainer("/var/lib/samba/private/tls/ca.pem", file.toString());
        }
        return file;
    }
}
