/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.gateway.EventKeys;
import io.radiusward.protocol.SessionStatus;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AckVerifierTest {

    private static final String HEADER = "session_id,status,session_time,acked,attempts,latency_ms";

    @TempDir
    Path dir;

    @Test
    void lastAcknowledgedIgnoresUnacknowledgedAndOlderEvents() {
        Map<String, AckVerifier.Expected> last = AckVerifier.lastAcknowledged(List.of(
                HEADER,
                "nas0-1,1,0,1,1,1.0",
                "nas0-1,3,10,1,1,1.0",
                "nas0-1,3,20,0,4,0.0",
                "nas0-2,1,0,1,1,1.0",
                "nas0-2,3,10,1,1,1.0",
                "nas0-2,2,10,1,2,1.0",
                ""));
        assertThat(last.get("nas0-1")).isEqualTo(new AckVerifier.Expected("nas0-1", 3, 10));
        assertThat(last.get("nas0-2")).isEqualTo(new AckVerifier.Expected("nas0-2", 2, 10));
    }

    @Test
    void reportsMissingOlderAndUnstoppedSessions() throws Exception {
        Path log = dir.resolve("acks.csv");
        Files.write(
                log,
                List.of(
                        HEADER,
                        "a-1,3,30,1,1,1",
                        "a-2,3,30,1,1,1",
                        "a-3,2,30,1,1,1",
                        "a-4,3,30,1,1,1",
                        "a-5,2,30,1,1,1"),
                StandardCharsets.UTF_8);
        Map<String, AdminClient.Session> state = new HashMap<>();
        state.put(key("a-1"), session(SessionStatus.ACTIVE, 40)); // newer than acknowledged: fine
        state.put(key("a-2"), session(SessionStatus.ACTIVE, 20)); // older: lost
        state.put(key("a-3"), session(SessionStatus.ACTIVE, 30)); // Stop lost
        state.put(key("a-5"), session(SessionStatus.STOPPED, 30));
        // a-4 missing entirely

        AckVerifier.Report report = AckVerifier.verify(
                log, 7, (hi, lo) -> state.getOrDefault(hi + ":" + lo, session(SessionStatus.UNKNOWN, 0)));

        assertThat(report.sessions()).isEqualTo(5);
        assertThat(report.ok()).isFalse();
        assertThat(report.lost())
                .hasSize(3)
                .anyMatch(l -> l.startsWith("a-2: session time 20"))
                .anyMatch(l -> l.startsWith("a-3: acknowledged Stop"))
                .anyMatch(l -> l.startsWith("a-4: missing"));
    }

    @Test
    void usageErrors() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8);
        PrintStream o = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        assertThat(AdminMain.run(new String[0], o, e)).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(AdminMain.run(new String[] {"state"}, o, e)).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(AdminMain.run(new String[] {"bogus", "--members", "x"}, o, e))
                .isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(AdminMain.run(new String[] {"verify-acks", "--members", "x"}, o, e))
                .isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(AdminMain.run(new String[] {"state", "--members"}, o, e)).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("usage: admin state");
    }

    @Test
    void exportSchemaPrintsTheFullSql() {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, StandardCharsets.UTF_8);
        PrintStream e = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        assertThat(AdminMain.run(new String[] {"export-schema"}, o, e)).isEqualTo(AdminMain.EXIT_OK);
        assertThat(out.toString(StandardCharsets.UTF_8))
                .contains("CREATE TABLE IF NOT EXISTS schema_version")
                .contains("CREATE TABLE accounting_session")
                .contains("PARTITION BY RANGE (commit_day)")
                .contains("INSERT INTO schema_version (version, name, checksum, applied_at) VALUES (1, 'V1__init.sql'");
        assertThat(AdminMain.run(new String[] {"export-schema", "--type", "oracle"}, o, e))
                .isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(AdminMain.run(new String[] {"resync", "--members", "x"}, o, e))
                .isEqualTo(AdminMain.EXIT_USAGE);
    }

    @Test
    void everyCommandChecksItsOptions() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8);
        PrintStream o = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        String[][] usage = {
            {"sinks"},
            {"resync", "--members", "x", "--sink", "pg"},
            {"verify-acks", "--members", "x", "--ack-log", "a.csv"},
            {"verify-export", "--jdbc-url", "jdbc:x"},
            {"verify-export", "--jdbc-url", "jdbc:x", "--ack-log", "a"},
            {"state", "members", "x"},
        };
        for (String[] args : usage) {
            assertThat(AdminMain.run(args, o, e)).as(String.join(" ", args)).isEqualTo(AdminMain.EXIT_USAGE);
        }
        assertThat(err.toString(StandardCharsets.UTF_8))
                .contains("--members is required")
                .contains("--position is required");
        // a database that is not there: a failure (1), not a usage error
        assertThat(AdminMain.run(
                        new String[] {
                            "verify-export",
                            "--jdbc-url",
                            "jdbc:postgresql://127.0.0.1:1/x",
                            "--ack-log",
                            "a.csv",
                            "--nas-id",
                            "1"
                        },
                        o,
                        e))
                .isEqualTo(AdminMain.EXIT_FAILED);
    }

    private static String key(String sessionId) {
        EventKeys keys = new EventKeys();
        UnsafeBuffer id = new UnsafeBuffer(sessionId.getBytes(StandardCharsets.US_ASCII));
        keys.compute(7, 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
        return keys.sessionHi() + ":" + keys.sessionLo();
    }

    private static AdminClient.Session session(SessionStatus status, long sessionTime) {
        return new AdminClient.Session(status, 7, 3, sessionTime, 0, 0, 0);
    }
}
