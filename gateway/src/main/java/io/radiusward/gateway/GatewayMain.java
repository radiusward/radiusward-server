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

    /**
     * SIGHUP reloads the configuration, as {@code systemctl reload} sends it; a failure keeps the running one. Through
     * reflection: {@code sun.misc.Signal} has no public replacement.
     */
    private static void onHangUp(java.util.function.Supplier<String> reload) {
        try {
            Class<?> signalType = Class.forName("sun.misc.Signal");
            Class<?> handlerType = Class.forName("sun.misc.SignalHandler");
            Object handler = java.lang.reflect.Proxy.newProxyInstance(
                    handlerType.getClassLoader(), new Class<?>[] {handlerType}, (proxy, method, arguments) -> {
                        switch (method.getName()) {
                            case "handle" -> {
                                try {
                                    reload.get();
                                } catch (RuntimeException e) {
                                    LogManager.getLogger(GatewayMain.class)
                                            .error(
                                                    "configuration not reloaded, the running one stays: {}",
                                                    e.getMessage());
                                }
                                return null;
                            }
                            case "hashCode" -> {
                                return System.identityHashCode(proxy);
                            }
                            case "equals" -> {
                                return proxy == arguments[0];
                            }
                            default -> {
                                return "SIGHUP reload";
                            }
                        }
                    });
            signalType
                    .getMethod("handle", signalType, handlerType)
                    .invoke(null, signalType.getConstructor(String.class).newInstance("HUP"), handler);
        } catch (ReflectiveOperationException | RuntimeException e) { // no SIGHUP on this platform or JDK
            LogManager.getLogger(GatewayMain.class)
                    .info("no SIGHUP handler ({}): reload with POST /reload", e.toString());
        }
    }

    public static void main(String[] args) {
        io.radiusward.common.net.DnsCache.shortLived(); // members are found by name; pods change address (ADR 0062)
        TlsCredentials.statefulSessions(); // before anything loads the JDK's TLS classes
        java.util.List<java.nio.file.Path> files =
                ConfigArgs.files(args, "gateway --config <file.properties> [--config ...]");
        Config config = Config.load(files, System.getenv());
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
            java.util.function.Supplier<String> reload =
                    () -> gateway.reload(Config.load(files, System.getenv())); // ADR 0054
            onHangUp(reload);
            String reloadToken = config.string("reload.api.token", "").trim();
            if (management != null && !reloadToken.isEmpty()) {
                management.handle("/reload", new ReloadApi(reloadToken, reload));
            }
            gateway.rejectDelay(Gateway.rejectDelay(config)); // ADR 0057
            gateway.authLog(config); // ADR 0058
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
