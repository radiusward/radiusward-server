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
import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * NAS entries from a database (ADR 0046) through the real gateway: no NAS is configured, {@code nas.dynamic.*} points
 * at PostgreSQL with a {@code nas} table in the usual layout. The first Access-Request from 127.0.0.1 is dropped while
 * the entry is looked up; the NAS's retransmission is answered, signed with the secret from the table. Skipped where
 * Docker is missing, a failure where it is required.
 */
@Epic("Transports")
@Feature("Dynamic NAS entries")
@Link(
        name = "ADR 0046",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0046-dynamic-clients.md")
class DynamicClientsIT {

    static final byte[] SECRET = "from-the-table".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private PostgreSQLContainer postgres;
    private Gateway gateway;

    @AfterEach
    void stop() {
        if (gateway != null) {
            gateway.close();
        }
        if (postgres != null) {
            postgres.stop();
        }
    }

    @Test
    void aNasFromTheTableIsAnsweredFromItsSecondRequestOn() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        postgres = new PostgreSQLContainer("postgres:17-alpine");
        postgres.start();
        long deadline = System.nanoTime() + 30_000_000_000L; // the mapped port may lag behind (Colima)
        while (true) {
            try (Connection probe = DriverManager.getConnection(
                    postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())) {
                if (probe.isValid(5)) {
                    break;
                }
            } catch (java.sql.SQLException e) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("PostgreSQL not reachable", e);
                }
                Thread.sleep(250);
            }
        }
        try (Connection c = DriverManager.getConnection(
                        postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
                Statement s = c.createStatement()) {
            s.execute("CREATE TABLE nas (id serial PRIMARY KEY, nasname text NOT NULL, shortname text,"
                    + " type text DEFAULT 'other', secret text NOT NULL)");
            s.execute("INSERT INTO nas (nasname, shortname, type, secret) VALUES ('127.0.0.1', 'lab-ap', 'cisco',"
                    + " 'from-the-table')");
        }
        Path users = Files.writeString(dir.resolve("users"), "nemo    Cleartext-Password := \"arctangent\"\n");
        Config config = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.plugins.dir", dir.resolve("no-plugins").toString()),
                Map.entry("nas.dynamic.enabled", "true"),
                Map.entry("nas.dynamic.networks", "127.0.0.0/8"),
                Map.entry("nas.dynamic.sql.url", postgres.getJdbcUrl()),
                Map.entry("nas.dynamic.sql.user", postgres.getUsername()),
                Map.entry("nas.dynamic.sql.password", postgres.getPassword())));
        NasRegistry registry = NasRegistry.from(config);
        assertThat(registry.clients()).isEmpty();
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        gateway = Gateway.launchWith(
                new GatewayConfig(
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
                        c.debugResponseDelay()),
                registry,
                auth,
                Gateway.storeHandler(config, auth));

        byte[] request = AuthAgentTest.accessRequest(1, "arctangent", true, false, SECRET);
        try (DatagramSocket nas = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            nas.setSoTimeout(1_000);
            byte[] answer = null;
            int sent = 0;
            while (answer == null && sent < 10) {
                nas.send(new DatagramPacket(
                        request, request.length, InetAddress.getLoopbackAddress(), gateway.authPort()));
                sent++;
                byte[] in = new byte[4096];
                DatagramPacket p = new DatagramPacket(in, in.length);
                try {
                    nas.receive(p);
                    answer = Arrays.copyOf(in, p.getLength());
                } catch (SocketTimeoutException e) {
                    // the NAS sends it again
                }
            }
            assertThat(sent)
                    .as("the first one is dropped while the entry is looked up")
                    .isGreaterThan(1);
            AuthAgentTest.assertSignedReplyTo(answer, request, RadiusCode.ACCESS_ACCEPT, SECRET);
        }
        assertThat(gateway.metrics())
                .contains("radiusward_gateway_nas_dynamic_total{gateway=\"1\",result=\"found\"} 1")
                .contains("radiusward_gateway_nas_dynamic_entries{gateway=\"1\"} 1");
    }
}
