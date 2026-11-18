/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

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
public final class ServerMain {

    private ServerMain() {}

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
                                    LogManager.getLogger(ServerMain.class)
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
            LogManager.getLogger(ServerMain.class)
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
        ServerConfig serverConfig = ServerConfig.from(config);
        NasRegistry registry = NasRegistry.from(config);
        AuthConfig auth = AuthConfig.from(config);
        try (ShutdownSignalBarrier barrier = new ShutdownSignalBarrier();
                RadiusServer radiusServer = RadiusServer.builder(serverConfig, registry)
                        .auth(auth)
                        .handlerFactory(RadiusServer.storeHandler(config, auth))
                        .radsec(RadsecConfig.from(config, serverConfig.listenHost()))
                        .coa(CoaConfig.from(config))
                        .proxy(ProxyConfig.from(config))
                        .start();
                ManagementServer management = ManagementServer.start(
                        config,
                        9189 + serverConfig.serverId(),
                        radiusServer::health,
                        radiusServer::ready,
                        radiusServer::stateJson,
                        radiusServer::metrics)) {
            java.util.function.Supplier<String> reload =
                    () -> radiusServer.reload(Config.load(files, System.getenv())); // ADR 0054
            onHangUp(reload);
            String reloadToken = config.string("reload.api.token", "").trim();
            if (management != null && !reloadToken.isEmpty()) {
                management.handle("/reload", new ReloadApi(reloadToken, reload));
            }
            radiusServer.rejectDelay(RadiusServer.rejectDelay(config)); // ADR 0057
            radiusServer.authLog(config); // ADR 0058
            com.sun.net.httpserver.HttpHandler traceApi = radiusServer.trace(config); // ADR 0052
            if (management != null && traceApi != null) {
                management.handle("/trace", traceApi);
            }
            if (management != null && radiusServer.coaApi() != null) {
                management.handle("/coa/", radiusServer.coaApi()); // ADR 0036, with coa.api.token only
            }
            barrier.await();
            drain(radiusServer, config.duration("gateway.shutdown.drain", java.time.Duration.ZERO));
        } finally {
            LogManager.shutdown();
        }
    }

    /** Not ready, still answering, for {@code drain} before the gateway closes (ADR 0062); nothing when zero. */
    static void drain(RadiusServer radiusServer, java.time.Duration drain) {
        if (drain.isZero() || drain.isNegative()) {
            return;
        }
        radiusServer.drain();
        LogManager.getLogger(ServerMain.class).info("draining for {} before shutdown", drain);
        try {
            Thread.sleep(drain.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
