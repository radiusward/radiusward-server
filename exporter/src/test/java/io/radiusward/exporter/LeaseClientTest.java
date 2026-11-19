/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import static org.assertj.core.api.Assertions.assertThat;

import io.aeron.Aeron;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A checkpoint never takes longer than its timeout, also while no member answers: the exporter's close waits for the
 * renewal thread only that long, and a renewal still connecting after it would outlive its member (ADR 0017).
 */
class LeaseClientTest {

    @TempDir
    Path dir;

    @Test
    void aCheckpointWithoutAClusterReturnsWithinItsTimeoutEveryTime() {
        SinkConfig sink = new SinkConfig("s", "file", true, 0, 0, false, 10, 10, 2000, Map.of());
        try (MediaDriver driver = MediaDriver.launchEmbedded(new MediaDriver.Context()
                        .aeronDirectoryName(dir.resolve("aeron").toString())
                        .threadingMode(ThreadingMode.SHARED)
                        .dirDeleteOnStart(true)
                        .dirDeleteOnShutdown(true));
                Aeron aeron = Aeron.connect(new Aeron.Context().aeronDirectoryName(driver.aeronDirectoryName()));
                LeaseClient lease = new LeaseClient(aeron, "0=localhost:" + unusedPort(), "localhost")) {
            for (int attempt = 0; attempt < 3; attempt++) {
                long started = System.nanoTime();
                assertThat(lease.checkpoint(sink, 0, 1, 0, 0, Duration.ofMillis(300)))
                        .as("no member answers")
                        .isNull();
                assertThat(Duration.ofNanos(System.nanoTime() - started))
                        .as("attempt %d within its timeout, not the 5 s of a connect", attempt)
                        .isLessThan(Duration.ofMillis(1500));
            }
            lease.close();
            lease.close();
        }
    }

    private static int unusedPort() {
        try (java.net.DatagramSocket s = new java.net.DatagramSocket(0)) {
            return s.getLocalPort();
        } catch (java.net.SocketException e) {
            throw new IllegalStateException(e);
        }
    }
}
