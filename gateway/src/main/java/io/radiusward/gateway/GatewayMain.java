/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.Profile;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigArgs;
import io.radiusward.common.logging.Logging;
import io.radiusward.common.management.ManagementServer;
import org.agrona.concurrent.ShutdownSignalBarrier;
import org.apache.logging.log4j.LogManager;

/**
 * {@code radiusward gateway --config gateway.properties --config nas-clients.properties}. No static logger:
 * logging is configured first.
 */
public final class GatewayMain {

    private GatewayMain() {}

    @SuppressWarnings("try") // the management server only has to stay open until shutdown
    public static void main(String[] args) {
        Config config = Config.load(
                ConfigArgs.files(args, "gateway --config <file.properties> [--config ...]"), System.getenv());
        Logging.configure(config.enumValue("profile", Profile.class, Profile.SMALL));
        GatewayConfig gatewayConfig = GatewayConfig.from(config);
        NasRegistry registry = NasRegistry.from(config);
        AuthConfig auth = AuthConfig.from(config);
        AuthStores stores = auth.enabled() ? AuthStores.from(config, auth.workers()) : null;
        try (ShutdownSignalBarrier barrier = new ShutdownSignalBarrier();
                Gateway gateway = Gateway.launchWith(
                        gatewayConfig,
                        registry,
                        auth,
                        dictionary -> new StoreAccessHandler(stores, dictionary, System::currentTimeMillis));
                ManagementServer ignored = ManagementServer.start(
                        config,
                        9189 + gatewayConfig.gatewayId(),
                        gateway::health,
                        gateway::ready,
                        gateway::stateJson,
                        gateway::metrics)) {
            barrier.await();
        } finally {
            LogManager.shutdown();
        }
    }
}
