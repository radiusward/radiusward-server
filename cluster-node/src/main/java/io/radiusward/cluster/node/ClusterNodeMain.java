/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.radiusward.common.Profile;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigArgs;
import io.radiusward.common.logging.Logging;
import io.radiusward.common.management.ManagementServer;
import org.agrona.concurrent.ShutdownSignalBarrier;
import org.apache.logging.log4j.LogManager;

/**
 * {@code radiusward cluster-node --config node-0.properties [--config more.properties]}. Runs until SIGTERM /
 * SIGINT or until the cluster terminates the member. No static logger: logging is configured first.
 */
public final class ClusterNodeMain {

    private ClusterNodeMain() {}

    @SuppressWarnings("try") // the management server only has to stay open until shutdown
    public static void main(String[] args) {
        io.radiusward.common.net.DnsCache.shortLived(); // members are found by name; pods change address (ADR 0062)
        Config config = Config.load(
                ConfigArgs.files(args, "cluster-node --config <file.properties> [--config ...]"), System.getenv());
        Logging.configure(config.enumValue("profile", Profile.class, Profile.SMALL));
        ClusterNodeConfig nodeConfig = ClusterNodeConfig.from(config);
        try (ShutdownSignalBarrier barrier = new ShutdownSignalBarrier();
                ClusterNode node = ClusterNode.launch(nodeConfig, barrier::signalAll);
                ManagementServer ignored = ManagementServer.start(
                        config,
                        9090 + nodeConfig.nodeId(),
                        node::health,
                        node::ready,
                        node::stateJson,
                        node::metrics)) {
            barrier.await();
            node.markTerminated();
        } finally {
            LogManager.shutdown();
        }
    }
}
