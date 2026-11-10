/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthLogTest {

    @TempDir
    Path dir;

    static void await(java.util.function.BooleanSupplier done) throws InterruptedException {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!done.getAsBoolean() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
    }

    @Test
    void dailyJsonLinesFiles() throws Exception {
        try (AuthLog log = AuthLog.from(
                Config.of(Map.of("auth.log.dir", dir.resolve("auth").toString())))) {
            assertThat(log.record(new AuthLog.Entry(
                            Instant.parse("2027-01-14T23:59:59Z"), "edge-1", "alice", "aa-bb", true, null)))
                    .isTrue();
            log.record(new AuthLog.Entry(
                    Instant.parse("2027-01-15T00:00:01Z"), "edge-1", "bo\"b", null, false, "user not in any store"));
            await(() -> log.written() == 2);
            assertThat(Files.readAllLines(dir.resolve("auth/auth-2027-01-14.jsonl")))
                    .containsExactly("{\"time\":\"2027-01-14T23:59:59Z\",\"nas\":\"edge-1\",\"user\":\"alice\","
                            + "\"station\":\"aa-bb\",\"result\":\"accept\"}");
            assertThat(Files.readAllLines(dir.resolve("auth/auth-2027-01-15.jsonl")))
                    .containsExactly("{\"time\":\"2027-01-15T00:00:01Z\",\"nas\":\"edge-1\",\"user\":\"bo\\\"b\","
                            + "\"station\":null,\"result\":\"reject\",\"reason\":\"user not in any store\"}");
        }
    }

    @Test
    void aFullQueueOrAFailingTargetLosesEntriesWithoutWaiting() throws Exception {
        Path file = Files.writeString(dir.resolve("not-a-directory"), "");
        try (AuthLog log = new AuthLog(1, file, null, new Properties(), "auth_log")) {
            int offered = 0;
            for (int i = 0; i < 1000; i++) {
                if (log.record(new AuthLog.Entry(Instant.now(), "n", "u", null, true, null))) {
                    offered++;
                }
            }
            int accepted = offered;
            await(() -> log.failed() == accepted);
            assertThat(log.dropped()).isEqualTo(1000 - offered).isPositive();
            assertThat(log.written()).isZero();
            io.radiusward.common.management.PrometheusWriter w = new io.radiusward.common.management.PrometheusWriter();
            log.writeMetrics(w, "1");
            assertThat(w.finish())
                    .contains("radiusward_gateway_auth_log_entries_total{gateway=\"1\",result=\"dropped\"}");
        }
    }

    @Test
    void configuration() {
        assertThat(AuthLog.from(Config.of(Map.of()))).isNull();
        assertThatThrownBy(() -> AuthLog.from(Config.of(Map.of("auth.log.dir", "x", "auth.log.queue", "0"))))
                .isInstanceOf(ConfigException.class);
        assertThatThrownBy(() -> AuthLog.from(
                        Config.of(Map.of("auth.log.sql.url", "jdbc:x", "auth.log.sql.table", "x; DROP TABLE y"))))
                .isInstanceOf(ConfigException.class);
        assertThat(List.of(AuthLog.json(new AuthLog.Entry(Instant.EPOCH, "n", null, null, false, null))))
                .containsExactly("{\"time\":\"1970-01-01T00:00:00Z\",\"nas\":\"n\",\"user\":null,\"station\":null,"
                        + "\"result\":\"reject\"}");
    }
}
