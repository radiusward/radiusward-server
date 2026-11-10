/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * SIGHUP reloads a gateway's configuration files (ADR 0054): a NAS entry first on another address does not get its
 * requests answered; after its file names the right address and the gateway gets SIGHUP, it does — the process keeps
 * running, its other settings unchanged.
 */
class ConfigReloadIT extends E2eTestBase {

    @Override
    void configure(ProcessCluster cluster) throws Exception {
        cluster.nasConfig("nas.local.address=192.0.2.1"); // overrides the loopback entry: no NAS for 127.0.0.1
    }

    @Test
    void hangUpReloadsTheNasEntries() throws Exception {
        int port = cluster.radiusPort("gateway-a");
        assertThat(nas.exchange(port, Nas.request(1, 1, "reload-1", 0), 2, Duration.ofMillis(500)))
                .as("unknown NAS")
                .isNull();
        cluster.nasConfig("");
        assertThat(Files.readString(dir.resolve("nas-clients.properties"))).doesNotContain("192.0.2.1");
        cluster.hangUp("gateway-a");
        nas.ack(port, Nas.request(2, 1, "reload-1", 0));
        assertThat(cluster.running("gateway-a")).isTrue();
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos(); // the log is written asynchronously
        while (!Files.readString(dir.resolve("gateway-a.log")).contains("configuration reloaded")
                && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        assertThat(Files.readString(dir.resolve("gateway-a.log"))).contains("configuration reloaded");
    }
}
