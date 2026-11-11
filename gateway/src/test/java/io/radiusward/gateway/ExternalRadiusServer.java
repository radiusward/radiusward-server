/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.IOException;
import java.net.DatagramSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * An installed external RADIUS server ({@code radiusd}) for {@code -Pinterop} tests: found on the path, in
 * {@code /opt/homebrew/bin}, {@code /usr/local/bin} or {@code /usr/sbin}, or by {@code -Dradiusward.interop.radiusd};
 * its dictionaries and modules next to it. It runs with a configuration of the test's own, written into a directory.
 */
final class ExternalRadiusServer implements AutoCloseable {

    final Path dir;
    private final Process process;

    private ExternalRadiusServer(Path dir, Process process) {
        this.dir = dir;
        this.process = process;
    }

    /** The installed binary, if any. */
    static Optional<Path> binary() {
        String configured = System.getProperty("radiusward.interop.radiusd", "");
        if (!configured.isBlank()) {
            return Optional.of(Path.of(configured)).filter(Files::isExecutable);
        }
        Stream<String> path = Stream.of(System.getenv().getOrDefault("PATH", "").split(java.io.File.pathSeparator));
        // radiusd from Homebrew or a source build; freeradius from the Debian and Ubuntu package (CI)
        return Stream.concat(path, Stream.of("/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/sbin"))
                .filter(d -> !d.isBlank())
                .flatMap(d -> Stream.of(Path.of(d, "radiusd"), Path.of(d, "freeradius")))
                .filter(Files::isExecutable)
                .findFirst();
    }

    static int freeUdpPort() throws IOException {
        try (DatagramSocket probe = new DatagramSocket(0)) {
            return probe.getLocalPort();
        }
    }

    /**
     * Starts the server with {@code body} (clients, modules, listeners, servers) after the general settings, and waits
     * until it is ready.
     */
    static ExternalRadiusServer start(Path binary, Path dir, String body) throws Exception {
        Path prefix = binary.toRealPath().getParent().getParent();
        Path dictionaries = Stream.of(prefix.resolve("share/freeradius/dictionary"))
                .filter(Files::isRegularFile)
                .findFirst()
                .or(() -> find(prefix.resolve("share"), "dictionary", 2))
                .map(Path::getParent)
                .orElseThrow();
        Path modules = Stream.of("rlm_always.so", "rlm_always.dylib")
                .map(name -> find(prefix.resolve("lib"), name, 3))
                .flatMap(Optional::stream)
                .map(Path::getParent)
                .findFirst()
                .orElseThrow();
        Files.createDirectories(dir.resolve("run"));
        Files.writeString(dir.resolve("radiusd.conf"), """
                prefix = %1$s
                raddbdir = %2$s
                confdir = %2$s
                run_dir = %2$s/run
                logdir = %2$s
                libdir = %3$s
                pidfile = %2$s/run/radiusd.pid
                max_request_time = 30
                cleanup_delay = 5
                max_requests = 1024
                hostname_lookups = no
                log {
                    destination = stdout
                }
                security {
                    allow_core_dumps = no
                }
                """.formatted(prefix, dir, modules) + body);
        Process process = new ProcessBuilder(
                        binary.toString(), "-X", "-d", dir.toString(), "-D", dictionaries.toString())
                .redirectErrorStream(true)
                .redirectOutput(dir.resolve("server.log").toFile())
                .start();
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (!Files.readString(dir.resolve("server.log")).contains("Ready to process requests")) {
            if (!process.isAlive() || System.nanoTime() > deadline) {
                throw new IllegalStateException(
                        "the external server did not start:\n" + Files.readString(dir.resolve("server.log")));
            }
            Thread.sleep(100);
        }
        return new ExternalRadiusServer(dir, process);
    }

    private static Optional<Path> find(Path root, String name, int depth) {
        if (!Files.isDirectory(root)) {
            return Optional.empty();
        }
        try (Stream<Path> files =
                Files.find(root, depth, (p, a) -> p.getFileName().toString().equals(name))) {
            return files.findFirst();
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /** Stops the server and keeps its log in {@code target/<logs>/server.log}. */
    void stop(String logs) throws IOException {
        process.destroy();
        Path out = Path.of("target", logs);
        Files.createDirectories(out);
        Files.copy(
                dir.resolve("server.log"),
                out.resolve("server.log"),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    @Override
    public void close() throws IOException {
        process.destroy();
    }
}
