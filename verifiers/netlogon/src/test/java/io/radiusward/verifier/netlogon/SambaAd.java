/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;

/**
 * A Samba AD domain controller for tests ({@code testing/samba-ad}): domain CORP.TEST, users alice (VPN Users, Staff;
 * through VPN Users also Remote Workers), bob (Staff), carol (disabled), service account svc-radius. Skipped where
 * Docker is missing, a failure where it is required.
 */
final class SambaAd {

    static final String BASE = "DC=corp,DC=test";
    static final String SERVICE = "CN=svc-radius,CN=Users," + BASE;
    static final String SERVICE_PASSWORD = "Svc-Passw0rd!";

    private static GenericContainer<?> container;

    private SambaAd() {}

    static synchronized GenericContainer<?> start() {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        if (container == null) {
            Path dir = Path.of("../../testing/samba-ad").toAbsolutePath().normalize();
            GenericContainer<?> c = new GenericContainer<>(new ImageFromDockerfile("radiusward-samba-ad:test", false)
                            .withFileFromPath("Dockerfile", dir.resolve("Dockerfile"))
                            .withFileFromPath("start.sh", dir.resolve("start.sh")))
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

    static final String MACHINE_ACCOUNT = "RADIUSWARD$";
    static final String MACHINE = "RADIUSWARD";
    static final String MACHINE_PASSWORD = "Machine-Passw0rd-1234567890";

    /** The endpoint mapper as the host reaches it. */
    static java.net.InetSocketAddress endpointMapper() {
        return new java.net.InetSocketAddress(container.getHost(), container.getMappedPort(135));
    }

    /** A port inside the container (what the endpoint mapper names) as the host reaches it. */
    static java.net.InetSocketAddress mapped(int port) {
        return new java.net.InetSocketAddress(container.getHost(), container.getMappedPort(port));
    }

    static String ldapUrl() {
        return "ldap://" + container.getHost() + ":" + container.getMappedPort(389);
    }

    static String ldapsUrl() {
        return "ldaps://" + container.getHost() + ":" + container.getMappedPort(636);
    }

    /** The CA that signed the domain controller's certificate, copied out of the container. */
    static Path ca(Path dir) throws Exception {
        Path file = dir.resolve("ca.pem");
        if (!Files.exists(file)) {
            container.copyFileFromContainer("/var/lib/samba/private/tls/ca.pem", file.toString());
        }
        return file;
    }
}
