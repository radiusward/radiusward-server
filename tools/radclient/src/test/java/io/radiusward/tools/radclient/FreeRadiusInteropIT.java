/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Sends every vendor fixture to a real FreeRADIUS and verifies the Accounting-Responses.
 *
 * <p>Runs only with {@code -Pinterop} and when {@code radiusd} is on the PATH
 * ({@code brew install freeradius-server}); skipped otherwise. No Docker involved.
 */
@Epic("Accounting")
@Feature("Interop with another RADIUS server")
class FreeRadiusInteropIT {

    @Test
    void fixturesAreAcceptedByFreeRadius(@TempDir Path dir) throws Exception {
        assumeTrue(Boolean.getBoolean("radiusward.interop"), "interop profile not active");
        Optional<Path> radiusd = findOnPath("radiusd");
        assumeTrue(radiusd.isPresent(), "radiusd not installed");

        int port;
        try (DatagramSocket probe = new DatagramSocket(0)) {
            port = probe.getLocalPort();
        }
        Path prefix = radiusd.get().toRealPath().getParent().getParent();
        writeConfig(dir, prefix, port);
        Process server = new ProcessBuilder(radiusd.get().toString(), "-f", "-X", "-d", dir.toString())
                .redirectErrorStream(true)
                .redirectOutput(dir.resolve("radiusd.log").toFile())
                .start();
        try {
            waitForReady(dir.resolve("radiusd.log"), server);
            List<Path> fixtures;
            try (Stream<Path> walk = Files.walk(Path.of("../../radius-codec/src/test/resources/fixtures"))) {
                fixtures = walk.filter(p -> p.toString().endsWith(".fixture"))
                        .sorted()
                        .toList();
            }
            assertThat(fixtures).hasSizeGreaterThanOrEqualTo(18);
            for (Path fixture : fixtures) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int code = new RadClient(
                                new PrintStream(out, true, StandardCharsets.UTF_8),
                                new PrintStream(out, true, StandardCharsets.UTF_8))
                        .run(new String[] {
                            "replay",
                            fixture.toString(),
                            "--server",
                            "127.0.0.1:" + port,
                            "--secret",
                            "testing123",
                            "--timeout",
                            "2s",
                            "--retries",
                            "1"
                        });
                assertThat(code)
                        .as("%s%n%s", fixture, out.toString(StandardCharsets.UTF_8))
                        .isEqualTo(RadClient.EXIT_OK);
            }
        } finally {
            server.destroy();
            server.waitFor();
        }
    }

    private static void writeConfig(Path dir, Path prefix, int port) throws IOException {
        Files.createDirectories(dir.resolve("run"));
        Files.writeString(dir.resolve("dictionary"), "# local dictionary (empty)\n");
        Files.writeString(dir.resolve("radiusd.conf"), """
                prefix = %s
                exec_prefix = ${prefix}
                sysconfdir = ${prefix}/etc
                localstatedir = %s
                sbindir = ${exec_prefix}/sbin
                logdir = %s
                raddbdir = %s
                radacctdir = %s
                name = radiusd
                confdir = %s
                run_dir = %s/run
                db_dir = %s
                libdir = ${exec_prefix}/lib
                pidfile = ${run_dir}/radiusd.pid
                max_request_time = 5
                cleanup_delay = 1
                max_requests = 1024
                hostname_lookups = no
                log {
                    destination = stdout
                }
                security {
                    allow_core_dumps = no
                }
                client localhost {
                    ipaddr = 127.0.0.1
                    secret = testing123
                }
                modules {
                    always ok {
                        rcode = ok
                    }
                }
                server default {
                    listen {
                        type = acct
                        ipaddr = 127.0.0.1
                        port = %d
                    }
                    preacct {
                        ok
                    }
                    accounting {
                        ok
                    }
                }
                """.formatted(prefix, dir, dir, dir, dir, dir, dir, dir, port));
    }

    private static void waitForReady(Path log, Process server) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            if (!server.isAlive()) {
                throw new AssertionError("radiusd exited:\n" + Files.readString(log));
            }
            if (Files.exists(log) && Files.readString(log).contains("Ready to process requests")) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("radiusd did not start:\n" + Files.readString(log));
    }

    private static Optional<Path> findOnPath(String binary) {
        for (String dir : System.getenv().getOrDefault("PATH", "").split(java.io.File.pathSeparator)) {
            Path candidate = Path.of(dir, binary);
            if (Files.isExecutable(candidate)) {
                return Optional.of(candidate);
            }
        }
        for (String dir : List.of("/opt/homebrew/sbin", "/opt/homebrew/bin", "/usr/local/sbin", "/usr/sbin")) {
            Path candidate = Path.of(dir, binary);
            if (Files.isExecutable(candidate)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }
}
