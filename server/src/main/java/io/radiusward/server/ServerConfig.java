/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.common.Profile;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

/** RADIUS server settings (see {@code docs/configuration.md}). */
public record ServerConfig(
        int serverId,
        String listenHost,
        int listenPort,
        int socketReceiveBuffer,
        List<String> clusterMembers,
        int clusterBasePort,
        String egressHost,
        Profile profile,
        int pendingCapacity,
        Duration pendingTimeout,
        Duration resubmitAfter,
        Duration responseCacheTtl,
        boolean dedicatedThreads,
        String idleStrategy,
        String aeronDir,
        Path dictionaryDir,
        Duration debugResponseDelay) {

    public static ServerConfig from(Config config) {
        Profile profile = config.enumValue("profile", Profile.class, Profile.SMALL);
        int id = config.integer("server.id", 1);
        boolean debug = config.bool("debug.enabled", false);
        Duration delay = config.duration("debug.response.delay", Duration.ZERO);
        if (!delay.isZero() && !debug) {
            throw new ConfigException(
                    "debug.response.delay: only allowed with debug.enabled=true (never in production)");
        }
        String threading = config.string("server.threading", profile == Profile.LARGE ? "dedicated" : "shared")
                .toLowerCase(Locale.ROOT);
        if (!threading.equals("shared") && !threading.equals("dedicated")) {
            throw new ConfigException("server.threading: expected shared or dedicated, got \"" + threading + "\"");
        }
        String idle = config.string("server.idle.strategy", profile.idleStrategyName());
        if (!Profile.IDLE_STRATEGIES.contains(idle)) {
            throw new ConfigException(
                    "server.idle.strategy: expected one of " + Profile.IDLE_STRATEGIES + ", got \"" + idle + "\"");
        }
        Path dictionaryDir = Path.of(config.string("dictionary.dir", "/etc/radiusward/dictionary.d"));
        return new ServerConfig(
                id,
                config.string("server.listen.host", "0.0.0.0"),
                config.integer("server.listen.port", 1813),
                (int) config.bytes("server.socket.receive.buffer", 4L << 20),
                config.list("cluster.members", List.of("localhost", "localhost", "localhost")),
                config.integer("cluster.base.port", 9000),
                config.string("server.egress.host", "localhost"),
                profile,
                config.integer("server.pending.capacity", profile.pendingRequests()),
                config.duration("server.pending.timeout", Duration.ofSeconds(5)),
                config.duration("server.retransmit.resubmit.after", Duration.ofSeconds(1)),
                config.duration("server.response.cache.ttl", Duration.ofSeconds(30)),
                threading.equals("dedicated"),
                idle,
                config.string(
                        "server.aeron.dir",
                        new File(
                                        System.getProperty("java.io.tmpdir"),
                                        "radiusward-server-" + id + "-"
                                                + ProcessHandle.current().pid())
                                .getPath()),
                Files.isDirectory(dictionaryDir) ? dictionaryDir : null,
                delay);
    }
}
