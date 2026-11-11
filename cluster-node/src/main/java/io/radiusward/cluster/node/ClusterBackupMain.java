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

/** {@code radiusward cluster-backup --config <file.properties>}: the continuous backup of ADR 0065. */
public final class ClusterBackupMain {

    private ClusterBackupMain() {}

    @SuppressWarnings("try") // the management server only has to stay open until shutdown
    public static void main(String[] args) {
        io.radiusward.common.net.DnsCache.shortLived(); // members are found by name; pods change address (ADR 0062)
        Config config = Config.load(
                ConfigArgs.files(args, "cluster-backup --config <file.properties> [--config ...]"), System.getenv());
        Logging.configure(config.enumValue("profile", Profile.class, Profile.SMALL));
        try (ShutdownSignalBarrier barrier = new ShutdownSignalBarrier();
                ClusterBackupNode backup = ClusterBackupNode.launch(ClusterBackupNode.Settings.from(config));
                ManagementServer ignored = ManagementServer.start(
                        config, 9090, backup::health, backup::ready, backup::stateJson, backup::metrics)) {
            barrier.await();
        } finally {
            LogManager.shutdown();
        }
    }
}
