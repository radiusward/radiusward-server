/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import io.radiusward.common.Profile;
import io.radiusward.common.logging.Logging;
import io.radiusward.common.management.ManagementServer;
import java.io.File;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.agrona.CloseHelper;
import org.agrona.concurrent.ShutdownSignalBarrier;

/**
 * Dev mode: three cluster members and two gateways in one JVM, on the same ports as
 * {@code scripts/run-local.sh} (RADIUS 1813/1814, management 9090-9092 and 9190/9191). Run from the IDE
 * (VM option {@code --add-exports java.base/jdk.internal.misc=ALL-UNNAMED}); state lives in .local/dev.
 */
public final class DevCluster {

    private DevCluster() {}

    public static void main(String[] args) {
        Logging.configure(Profile.SMALL);
        File dir = new File(args.length > 0 ? args[0] : ".local/dev");
        long start = System.nanoTime();
        List<ManagementServer> servers = new ArrayList<>();
        try (ShutdownSignalBarrier barrier = new ShutdownSignalBarrier();
                LocalCluster cluster =
                        LocalCluster.start(dir, 3, 2, 9000, new int[] {1813, 1814}, Duration.ofHours(1))) {
            for (int i = 0; i < 3; i++) {
                var node = cluster.node(i);
                servers.add(ManagementServer.start(
                        "127.0.0.1", 9090 + i, node::health, node::ready, node::stateJson, node::metrics));
            }
            for (int g = 0; g < 2; g++) {
                var gateway = cluster.gateway(g);
                servers.add(ManagementServer.start(
                        "127.0.0.1", 9190 + g, gateway::health, gateway::ready, gateway::stateJson, gateway::metrics));
            }
            cluster.awaitLeader();
            cluster.awaitGatewaysConnected();
            System.out.printf(
                    "radiusward dev cluster ready in %d ms: RADIUS 127.0.0.1:1813 and :1814 (secret %s), state http://127.0.0.1:9090/state%n",
                    (System.nanoTime() - start) / 1_000_000, LocalCluster.SECRET);
            barrier.await();
        } finally {
            servers.forEach(CloseHelper::quietClose);
        }
    }
}
