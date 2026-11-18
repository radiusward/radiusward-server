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

/** {@code admin disconnect} and {@code admin coa} against a stand-in for a RADIUS server's CoA API (ADR 0036). */
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
            String radiusServer =
                    "http://127.0.0.1:" + server.getAddress().getPort() + "//"; // trailing slashes dropped
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            assertThat(AdminMain.run(
                            new String[] {"disconnect", "--server", radiusServer, "--user", "al ice", "--token", "t0k3n"
                            },
                            new PrintStream(out),
                            System.err))
                    .isZero();
            assertThat(out.toString(StandardCharsets.UTF_8)).contains("\"ack\"");
            answer[0] = "{\"sessions\":[{\"result\":\"nak\"}]}";
            assertThat(AdminMain.run(
                            new String[] {
                                "coa",
                                "--server",
                                radiusServer,
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

    @Test
    void aStatusOtherThan200Fails() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", e -> {
            byte[] body = "{\"error\":\"bad token\"}".getBytes(StandardCharsets.UTF_8);
            e.sendResponseHeaders(401, body.length);
            e.getResponseBody().write(body);
            e.close();
        });
        server.start();
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            assertThat(AdminMain.run(
                            new String[] {
                                "disconnect",
                                "--server",
                                "http://127.0.0.1:" + server.getAddress().getPort(),
                                "--user",
                                "alice",
                                "--token",
                                "wrong"
                            },
                            new PrintStream(out),
                            new PrintStream(new ByteArrayOutputStream())))
                    .isEqualTo(AdminMain.EXIT_FAILED);
            assertThat(out.toString(StandardCharsets.UTF_8)).contains("bad token");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void aTargetAndATokenAreRequiredBeforeAnythingIsSent() {
        String[][] runs = {
            {"disconnect", "--server", "http://127.0.0.1:1", "--token", "t"},
            {"disconnect", "--server", "http://127.0.0.1:1", "--token", "t", "--nas", "edge"},
            {"coa", "--server", "http://127.0.0.1:1", "--token", "t", "--session", "s-1", "--attributes", "x"},
            {"disconnect", "--server", "http://127.0.0.1:1", "--user", "alice", "--token", " "},
        };
        String[] expected = {
            "admin: --user <name>, or --nas <entry> --session <Acct-Session-Id>",
            "admin: --user <name>, or --nas <entry> --session <Acct-Session-Id>",
            "admin: --user <name>, or --nas <entry> --session <Acct-Session-Id>",
            "admin: --token or RADIUSWARD_COA_API_TOKEN",
        };
        for (int i = 0; i < runs.length; i++) {
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            assertThat(AdminMain.run(runs[i], new PrintStream(new ByteArrayOutputStream()), new PrintStream(err)))
                    .as(String.join(" ", runs[i]))
                    .isEqualTo(AdminMain.EXIT_USAGE);
            assertThat(err.toString(StandardCharsets.UTF_8))
                    .startsWith(expected[i])
                    .contains("usage:");
        }
    }

    @Test
    void withoutTheOptionTheTokenComesFromTheEnvironment() {
        String fromEnvironment = System.getenv("RADIUSWARD_COA_API_TOKEN");
        org.junit.jupiter.api.Assumptions.assumeTrue(
                fromEnvironment == null || fromEnvironment.isBlank(), "a token is set in the environment");
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        assertThat(AdminMain.run(
                        new String[] {"disconnect", "--server", "http://127.0.0.1:1", "--user", "alice"},
                        new PrintStream(new ByteArrayOutputStream()),
                        new PrintStream(err)))
                .isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("--token or RADIUSWARD_COA_API_TOKEN");
    }

    @Test
    void aServerOfOnlySlashesIsNoAddress() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        assertThat(AdminMain.run(
                        new String[] {"disconnect", "--server", "//", "--user", "alice", "--token", "t"},
                        new PrintStream(new ByteArrayOutputStream()),
                        new PrintStream(err)))
                .isEqualTo(AdminMain.EXIT_FAILED);
        assertThat(err.toString(StandardCharsets.UTF_8)).startsWith("admin: ");
    }
}
