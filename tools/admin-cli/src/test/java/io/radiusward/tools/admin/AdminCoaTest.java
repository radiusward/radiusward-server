/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** {@code admin disconnect} and {@code admin coa} against a stand-in for a gateway's CoA API (ADR 0036). */
class AdminCoaTest {

    @Test
    void requestsGoToTheApiAndNaksFail() throws Exception {
        List<String> seen = new ArrayList<>();
        String[] answer = {"{\"sessions\":[{\"result\":\"ack\"}]}"};
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", e -> {
            seen.add(e.getRequestMethod() + " " + e.getRequestURI() + " "
                    + e.getRequestHeaders().getFirst("Authorization") + " "
                    + new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] body = answer[0].getBytes(StandardCharsets.UTF_8);
            e.sendResponseHeaders(200, body.length);
            e.getResponseBody().write(body);
            e.close();
        });
        server.start();
        try {
            String gateway = "http://127.0.0.1:" + server.getAddress().getPort() + "//"; // trailing slashes dropped
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            assertThat(AdminMain.run(
                            new String[] {"disconnect", "--gateway", gateway, "--user", "al ice", "--token", "t0k3n"},
                            new PrintStream(out),
                            System.err))
                    .isZero();
            assertThat(out.toString(StandardCharsets.UTF_8)).contains("\"ack\"");
            answer[0] = "{\"sessions\":[{\"result\":\"nak\"}]}";
            assertThat(AdminMain.run(
                            new String[] {
                                "coa",
                                "--gateway",
                                gateway,
                                "--nas",
                                "edge",
                                "--session",
                                "s-1",
                                "--token",
                                "t0k3n",
                                "--attributes",
                                "Session-Timeout = 60"
                            },
                            new PrintStream(new ByteArrayOutputStream()),
                            System.err))
                    .isNotZero();
            assertThat(seen)
                    .containsExactly(
                            "POST /coa/disconnect?user=al+ice Bearer t0k3n ",
                            "POST /coa/update?nas=edge&session=s-1 Bearer t0k3n Session-Timeout = 60");
        } finally {
            server.stop(0);
        }
    }
}
