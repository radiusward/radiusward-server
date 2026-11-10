/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.function.Function;
import java.util.function.LongSupplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The rules file ({@code auth.rules}, ADR 0051), checked for changes at most every {@code auth.rules.reload.interval}
 * by the worker that asks; a change that does not parse keeps the previous rules and is logged.
 */
final class RulesFile {

    private static final Logger LOG = LogManager.getLogger(RulesFile.class);

    private final Path path;
    private final long intervalMillis;
    private final Function<String, Boolean> known;
    private final LongSupplier clockMillis;
    private volatile Rules rules;
    private volatile long modified;
    private volatile long nextCheck;

    RulesFile(Path path, Duration interval, Function<String, Boolean> known, LongSupplier clockMillis) {
        this.path = path;
        this.intervalMillis = interval.toMillis();
        this.known = known;
        this.clockMillis = clockMillis;
        try {
            this.modified = Files.getLastModifiedTime(path).toMillis();
            this.rules = Rules.parse(Files.readString(path, StandardCharsets.UTF_8), known);
        } catch (IOException | Rules.RuleException e) {
            throw new ConfigException("auth.rules " + path + ": " + e.getMessage(), e);
        }
        this.nextCheck = clockMillis.getAsLong() + intervalMillis;
        LOG.info("rules {}: {} rules", path, rules.rules().size());
    }

    /** {@code auth.rules}; {@code null} without. */
    static RulesFile from(Config config, Function<String, Boolean> known) {
        String path = config.string("auth.rules", "").trim();
        if (path.isEmpty()) {
            return null;
        }
        return new RulesFile(
                Path.of(path),
                config.duration("auth.rules.reload.interval", Duration.ofSeconds(5)),
                known,
                System::currentTimeMillis);
    }

    Rules current() {
        long now = clockMillis.getAsLong();
        if (intervalMillis > 0 && now >= nextCheck) {
            synchronized (this) {
                if (now >= nextCheck) {
                    nextCheck = now + intervalMillis;
                    reload();
                }
            }
        }
        return rules;
    }

    private void reload() {
        try {
            long m = Files.getLastModifiedTime(path).toMillis();
            if (m == modified) {
                return;
            }
            modified = m;
            rules = Rules.parse(Files.readString(path, StandardCharsets.UTF_8), known);
            LOG.info("rules {} reloaded: {} rules", path, rules.rules().size());
        } catch (IOException | Rules.RuleException e) {
            LOG.warn("rules {}: not reloaded, the previous rules stay: {}", path, e.getMessage());
        }
    }
}
