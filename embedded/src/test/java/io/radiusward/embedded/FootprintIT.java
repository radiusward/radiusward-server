/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.client.RadiusClient;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.management.BufferPoolMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * How long an embedded server takes to start and what it occupies, printed for the documentation (docs/embedded.md):
 * heap, direct buffers, the growth of the process's resident memory, and the files on disk. Aeron's memory-mapped files
 * (term buffers, counters) add virtual address space, of which only what is touched becomes resident. Fails only far
 * above the targets (2 s, 256 MB), so a slow machine does not fail the build.
 */
class FootprintIT {

    @Test
    void startupTimeAndMemory() {
        EmbeddedRadiusward.builder().user("warm", "up").start().close(); // classes loaded once, as in a test suite
        MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
        System.gc();
        long heapBefore = memory.getHeapMemoryUsage().getUsed();
        long directBefore = pool("direct");
        long rssBefore = residentKb();
        long started = System.nanoTime();
        try (EmbeddedRadiusward radius =
                        EmbeddedRadiusward.builder().user("alice", "secret").start();
                RadiusClient nas = radius.client()) {
            Duration startup = Duration.ofNanos(System.nanoTime() - started);
            assertThat(nas.pap("alice", "secret").orElseThrow().isAccept()).isTrue();
            System.gc();
            long heap = memory.getHeapMemoryUsage().getUsed() - heapBefore;
            long direct = pool("direct") - directBefore;
            long resident = rssBefore < 0 ? -1 : (residentKb() - rssBefore) << 10;
            System.out.printf(
                    "embedded radiusward: started in %d ms; heap %d MB, direct buffers %d MB, resident memory +%d MB,"
                            + " files %d MB (mapped address space %d MB)%n",
                    startup.toMillis(),
                    heap >> 20,
                    direct >> 20,
                    resident >> 20,
                    diskUse(radius.directory()) >> 20,
                    pool("mapped") >> 20);
            assertThat(startup).isLessThan(Duration.ofSeconds(20));
            assertThat(heap + direct).isLessThan(1L << 30);
        }
    }

    private static long pool(String name) {
        return ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class).stream()
                .filter(p -> p.getName().equals(name))
                .mapToLong(BufferPoolMXBean::getMemoryUsed)
                .sum();
    }

    /** This process's resident set in KB from {@code ps}; -1 where there is none. */
    private static long residentKb() {
        try {
            Process ps = new ProcessBuilder(
                            "ps",
                            "-o",
                            "rss=",
                            "-p",
                            Long.toString(ProcessHandle.current().pid()))
                    .redirectErrorStream(true)
                    .start();
            String out = new String(ps.getInputStream().readAllBytes(), StandardCharsets.US_ASCII).trim();
            return ps.waitFor() == 0 ? Long.parseLong(out) : -1;
        } catch (IOException | NumberFormatException e) {
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        }
    }

    /** Blocks actually allocated would be better; the sizes of the files are what a developer sees. */
    private static long diskUse(Path dir) {
        try (Stream<Path> files = Files.walk(dir)) {
            return files.filter(Files::isRegularFile)
                    .mapToLong(f -> {
                        try {
                            return Files.size(f);
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                    })
                    .sum();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
