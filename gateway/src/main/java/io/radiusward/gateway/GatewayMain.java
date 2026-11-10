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

    public static void main(String[] args) {
        TlsCredentials.statefulSessions(); // before anything loads the JDK's TLS classes
        Config config = Config.load(
                ConfigArgs.files(args, "gateway --config <file.properties> [--config ...]"), System.getenv());
        Logging.configure(config.enumValue("profile", Profile.class, Profile.SMALL));
        GatewayConfig gatewayConfig = GatewayConfig.from(config);
        NasRegistry registry = NasRegistry.from(config);
        AuthConfig auth = AuthConfig.from(config);
        try (ShutdownSignalBarrier barrier = new ShutdownSignalBarrier();
                Gateway gateway = Gateway.launchWith(
                        gatewayConfig,
                        registry,
                        auth,
                        Gateway.storeHandler(config, auth),
                        RadsecConfig.from(config, gatewayConfig.listenHost()),
                        CoaConfig.from(config),
                        ProxyConfig.from(config));
                ManagementServer management = ManagementServer.start(
                        config,
                        9189 + gatewayConfig.gatewayId(),
                        gateway::health,
                        gateway::ready,
                        gateway::stateJson,
                        gateway::metrics)) {
            com.sun.net.httpserver.HttpHandler traceApi = gateway.trace(config); // ADR 0052
            if (management != null && traceApi != null) {
                management.handle("/trace", traceApi);
            }
            if (management != null && gateway.coaApi() != null) {
                management.handle("/coa/", gateway.coaApi()); // ADR 0036, with coa.api.token only
            }
            barrier.await();
        } finally {
            LogManager.shutdown();
        }
    }
}
