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
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Disconnect- and CoA-Requests from the gateway's sender to an external RADIUS server acting as the NAS's dynamic
 * authorization server (RFC 5176, ADR 0036): an implementation we did not write checks our Request Authenticator,
 * Message-Authenticator and attributes, and answers ACK, NAK or nothing (a wrong secret).
 *
 * <p>Runs only with {@code -Pinterop} and an installed {@code radiusd} (on the path, in {@code /opt/homebrew/bin} or
 * {@code /usr/sbin}, or {@code -Dradiusward.interop.radiusd=<binary>}); its dictionaries and modules are found next to
 * it. The server gets a configuration of its own: a CoA listener on a free port that NAKs user {@code carol}.
 */
@Epic("Authentication")
@Feature("CoA and Disconnect")
@Link(
        name = "ADR 0036",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0036-coa-and-session-identity.md")
class ExternalCoaReceiverIT {

    static final byte[] SECRET = "coa-interop-secret".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    static Path dir;

    static ExternalRadiusServer server;
    static int port;
    static DynamicAuthorization sender;

    @BeforeAll
    static void start() throws Exception {
        assumeTrue(Boolean.getBoolean("radiusward.interop"), "interop profile not active");
        Optional<Path> binary = ExternalRadiusServer.binary();
        assumeTrue(binary.isPresent(), "no radiusd installed");
        port = ExternalRadiusServer.freeUdpPort();
        server = ExternalRadiusServer.start(
                binary.get(), dir, """
                modules {
                    always ok {
                        rcode = ok
                    }
                    always reject {
                        rcode = reject
                    }
                }
                client gateway {
                    ipaddr = 127.0.0.1
                    secret = %1$s
                    require_message_authenticator = yes
                }
                listen {
                    type = coa
                    ipaddr = 127.0.0.1
                    port = %2$d
                    virtual_server = coa
                }
                server coa {
                    recv-coa {
                        if (&User-Name == "carol") {
                            reject
                        }
                        else {
                            ok
                        }
                    }
                    send-coa {
                        ok
                    }
                }
                """.formatted(new String(SECRET, StandardCharsets.US_ASCII), port));
        sender = new DynamicAuthorization(
                new CoaConfig(true, Duration.ofMillis(500), 1, null, Map.of()), "127.0.0.1", null);
        sender.onStart();
    }

    @AfterAll
    static void stop() throws IOException {
        if (sender != null) {
            sender.onClose();
        }
        if (server != null) {
            server.stop("external-coa-receiver");
        }
    }

    private static DynamicAuthorization.Result exchange(int code, byte[] attributes, byte[] secret) throws Exception {
        var f = sender.send(code, attributes, new InetSocketAddress("127.0.0.1", port), secret);
        for (int i = 0; i < 1000 && !f.isDone(); i++) {
            sender.doWork();
            Thread.sleep(2);
        }
        return f.getNow(null);
    }

    static byte[] identity(String sessionId, String user) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (Object[] a : List.of(new Object[] {44, sessionId}, new Object[] {1, user})) {
            byte[] v = ((String) a[1]).getBytes(StandardCharsets.UTF_8);
            out.write((Integer) a[0]);
            out.write(2 + v.length);
            out.writeBytes(v);
        }
        out.writeBytes(new byte[] {4, 6, 127, 0, 0, 1}); // NAS-IP-Address
        return out.toByteArray();
    }

    @Test
    void disconnectAndCoaAreAcknowledged() throws Exception {
        assertThat(exchange(DynamicAuthorization.DISCONNECT_REQUEST, identity("s-1", "alice"), SECRET))
                .isEqualTo(new DynamicAuthorization.Result(DynamicAuthorization.Outcome.ACK, 0));
        byte[] coa = identity("s-1", "alice");
        byte[] withTimeout = java.util.Arrays.copyOf(coa, coa.length + 6);
        System.arraycopy(new byte[] {27, 6, 0, 0, 2, 88}, 0, withTimeout, coa.length, 6); // Session-Timeout 600
        assertThat(exchange(DynamicAuthorization.COA_REQUEST, withTimeout, SECRET)
                        .outcome())
                .isEqualTo(DynamicAuthorization.Outcome.ACK);
    }

    @Test
    void refusedOrUnansweredRequests() throws Exception {
        assertThat(exchange(DynamicAuthorization.DISCONNECT_REQUEST, identity("s-2", "carol"), SECRET)
                        .outcome())
                .as("the server's policy refuses carol")
                .isEqualTo(DynamicAuthorization.Outcome.NAK);
        assertThat(exchange(
                                DynamicAuthorization.COA_REQUEST,
                                identity("s-3", "alice"),
                                "wrong-secret".getBytes(StandardCharsets.US_ASCII))
                        .outcome())
                .as("a wrong secret: the server stays silent")
                .isEqualTo(DynamicAuthorization.Outcome.TIMEOUT);
    }
}
