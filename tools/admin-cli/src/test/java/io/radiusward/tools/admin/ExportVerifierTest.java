/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.export.Attributes;
import io.radiusward.export.Batch;
import io.radiusward.export.SessionSnapshot;
import io.radiusward.export.SinkContext;
import io.radiusward.gateway.EventKeys;
import io.radiusward.protocol.SessionStatus;
import io.radiusward.radius.dictionary.DictionaryLoader;
import io.radiusward.sink.postgres.PostgresSink;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** {@code admin verify-export} finds every kind of problem in a real database. Skipped without Docker. */
class ExportVerifierTest {

    private static final int NAS = 7;
    private static PostgreSQLContainer postgres;

    @TempDir
    Path dir;

    @BeforeAll
    static void start() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        postgres = new PostgreSQLContainer("postgres:17-alpine");
        postgres.start();
        long deadline = System.nanoTime() + 30_000_000_000L; // Colima forwards the port shortly after start
        while (true) {
            try (Connection c = connect()) {
                if (c.isValid(5)) {
                    return;
                }
            } catch (java.sql.SQLException e) {
                if (System.nanoTime() > deadline) {
                    throw e;
                }
                Thread.sleep(250);
            }
        }
    }

    @AfterAll
    static void stop() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    private static Connection connect() throws java.sql.SQLException {
        return DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
    }

    private static UUID key(String sessionId) {
        EventKeys keys = new EventKeys();
        UnsafeBuffer id = new UnsafeBuffer(sessionId.getBytes(StandardCharsets.US_ASCII));
        keys.compute(NAS, 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
        return new UUID(keys.sessionHi(), keys.sessionLo());
    }

    private static SessionSnapshot row(String id, long version, SessionSnapshot.State state, long seconds) {
        return new SessionSnapshot(
                key(id),
                version,
                NAS,
                id,
                state,
                SessionSnapshot.CloseCause.NONE,
                3,
                seconds,
                seconds,
                seconds,
                System.currentTimeMillis(),
                null,
                null,
                null);
    }

    @Test
    void findsMissingBehindUnstoppedAndDifferentSessions() throws Exception {
        try (PostgresSink sink = new PostgresSink()) {
            sink.open(new SinkContext(
                    "pg",
                    0,
                    Map.of(
                            "url",
                            postgres.getJdbcUrl(),
                            "user",
                            postgres.getUsername(),
                            "password",
                            postgres.getPassword()),
                    new Attributes(DictionaryLoader.loadBundled())));
            List<SessionSnapshot> rows = new ArrayList<>();
            rows.add(row("ok", 1, SessionSnapshot.State.STOPPED, 30));
            rows.add(row("behind", 2, SessionSnapshot.State.ACTIVE, 10));
            rows.add(row("not-stopped", 3, SessionSnapshot.State.ACTIVE, 30));
            rows.add(row("differs", 4, SessionSnapshot.State.ACTIVE, 40));
            sink.write(new Batch("pg", 1, 0, 100, 0, List.of(), rows));
        }
        Path acks = Files.write(
                dir.resolve("acks.csv"),
                List.of(
                        "session_id,status,session_time,acked,attempts,latency_ms",
                        "ok,2,30,1,1,1",
                        "behind,3,30,1,1,1",
                        "not-stopped,2,30,1,1,1",
                        "differs,3,30,1,1,1",
                        "missing,3,30,1,1,1"));
        // the cluster says "differs" is at 30 s, the database at 40 s
        AckVerifier.SessionLookup cluster = (hi, lo) -> new AdminClient.Session(
                new UUID(hi, lo).equals(key("ok")) ? SessionStatus.STOPPED : SessionStatus.ACTIVE, NAS, 3, 30, 0, 0, 0);
        try (Connection c = connect()) {
            AckVerifier.Report withoutCluster = ExportVerifier.verify(acks, NAS, c, null);
            assertThat(withoutCluster.sessions()).isEqualTo(5);
            assertThat(withoutCluster.lost())
                    .hasSize(3)
                    .anyMatch(l -> l.startsWith("missing: not in accounting_session"))
                    .anyMatch(l -> l.startsWith("behind: session_seconds 10 < acknowledged 30"))
                    .anyMatch(l -> l.startsWith("not-stopped: acknowledged Stop"));
            AckVerifier.Report withCluster = ExportVerifier.verify(acks, NAS, c, cluster);
            assertThat(withCluster.lost()).hasSize(4).anyMatch(l -> l.startsWith("differs: database"));
        }
    }
}
