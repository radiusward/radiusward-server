/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.client.PacketBuilder;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.testing.Ports;
import io.radiusward.testing.Reports;
import java.nio.file.Files;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Authentication is decided on the RADIUS server and goes on without a majority of the cluster (ADR 0020): a user of
 * the users file is accepted, a wrong password rejected, while accounting gets no answer. Only what has to be agreed
 * across RADIUS servers waits for the cluster: a user with Simultaneous-Use gets no answer (ADR 0023) until a majority
 * is back, and then the NAS's retry is accepted.
 */
@Epic("Authentication")
@Feature("Without a cluster majority")
@Link(
        name = "ADR 0023",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0023-simultaneous-use.md")
class AuthWithoutMajorityIT extends E2eTestBase {

    private int authPort;
    private int identifier;

    @Override
    void configure(ProcessCluster cluster) throws Exception {
        authPort = Ports.freePort();
        var users = Files.writeString(dir.resolve("users"), """
                alice Cleartext-Password := "alice-pw"
                carol Cleartext-Password := "carol-pw", Simultaneous-Use := 1
                """);
        cluster.serverConfig("server-a", """
                server.auth.enabled=true
                server.auth.port=%d
                server.auth.reservation.timeout=500ms
                auth.stores=local
                auth.store.local.type=file
                auth.store.local.path=%s
                auth.reject.delay=0s
                """.formatted(authPort, users));
    }

    @Test
    void loginsGoOnAndOnlySharedLimitsWait() throws Exception {
        assertThat(code(pap("alice", "alice-pw", null)))
                .as("with the whole cluster")
                .isEqualTo(RadiusCode.ACCESS_ACCEPT);

        String leader = cluster.awaitLeader();
        List<String> others = List.of("node-0", "node-1", "node-2").stream()
                .filter(n -> !n.equals(leader))
                .toList();
        cluster.kill(others.get(0));
        cluster.kill(others.get(1));

        Reports.step("one member left: logins are decided as before", () -> {
            assertThat(code(pap("alice", "alice-pw", null))).isEqualTo(RadiusCode.ACCESS_ACCEPT);
            assertThat(code(pap("alice", "wrong", null))).isEqualTo(RadiusCode.ACCESS_REJECT);
            assertThat(code(pap("nobody", "x", null))).isEqualTo(RadiusCode.ACCESS_REJECT);
        });
        Reports.step("accounting and Simultaneous-Use wait for a majority", () -> {
            assertThat(nas.exchange(
                            cluster.radiusPort("server-a"),
                            Nas.request(1, 1, "no-majority-1", 0),
                            2,
                            Duration.ofSeconds(2)))
                    .as("no Accounting-Response without a commit")
                    .isNull();
            assertThat(nas.answer(authPort, pap("carol", "carol-pw", "aa-bb-cc-00-00-01"), 2, Duration.ofSeconds(2)))
                    .as("the place cannot be reserved: no answer, the NAS retries")
                    .isNull();
        });

        cluster.start(others.get(0));
        cluster.awaitReady(others.get(0));
        Reports.step("a majority again: the retry of the limited user is accepted", () -> {
            byte[] reply =
                    nas.answer(authPort, pap("carol", "carol-pw", "aa-bb-cc-00-00-01"), 10, Duration.ofSeconds(2));
            assertThat(reply).as("answered once the cluster commits").isNotNull();
            assertThat(reply[0] & 0xFF).isEqualTo(RadiusCode.ACCESS_ACCEPT);
        });
    }

    /** A PAP Access-Request from the NAS entry, with Message-Authenticator and, if given, the device. */
    private byte[] pap(String user, String password, String station) {
        PacketBuilder request = PacketBuilder.accessRequest(++identifier)
                .messageAuthenticator()
                .attribute(1, user)
                .password(password);
        if (station != null) {
            request.attribute(31, station);
        }
        return request.secret(Nas.SECRET).build();
    }

    private int code(byte[] request) {
        byte[] reply = nas.answer(authPort, request, 3, Duration.ofSeconds(3));
        assertThat(reply).as("an answer without the cluster").isNotNull();
        return reply[0] & 0xFF;
    }
}
