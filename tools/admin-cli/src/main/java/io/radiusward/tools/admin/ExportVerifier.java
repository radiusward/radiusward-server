/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import io.radiusward.gateway.EventKeys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * {@code radiusward admin verify-export}: every session of an acknowledgement log ({@code radclient load
 * --ack-log}) must be in the database's {@code accounting_session} with at least the acknowledged progress, and
 * stopped if its Stop was acknowledged. With a cluster connection the row must equal the replicated session.
 */
public final class ExportVerifier {

    private ExportVerifier() {}

    public static AckVerifier.Report verify(Path ackLog, int nasId, Connection db, AdminClient cluster)
            throws IOException, SQLException {
        Map<String, AckVerifier.Expected> expected =
                AckVerifier.lastAcknowledged(Files.readAllLines(ackLog, StandardCharsets.UTF_8));
        EventKeys keys = new EventKeys();
        List<String> problems = new ArrayList<>();
        try (PreparedStatement ps =
                db.prepareStatement("SELECT state, session_seconds FROM accounting_session WHERE session_key = ?")) {
            for (AckVerifier.Expected e : expected.values()) {
                UnsafeBuffer id = new UnsafeBuffer(e.sessionId().getBytes(StandardCharsets.US_ASCII));
                keys.compute(nasId, 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
                ps.setObject(1, new UUID(keys.sessionHi(), keys.sessionLo()));
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        problems.add(e.sessionId() + ": not in accounting_session");
                        continue;
                    }
                    int state = rs.getInt(1);
                    long seconds = rs.getLong(2);
                    if (seconds < e.sessionTime()) {
                        problems.add(
                                e.sessionId() + ": session_seconds " + seconds + " < acknowledged " + e.sessionTime());
                    } else if (e.status() == 2 && state != 2) {
                        problems.add(e.sessionId() + ": acknowledged Stop, database has an active session");
                    } else if (cluster != null) {
                        AdminClient.Session replicated = cluster.session(keys.sessionHi(), keys.sessionLo());
                        boolean stopped = replicated.status() == io.radiusward.protocol.SessionStatus.STOPPED;
                        if ((state == 2) != stopped || seconds != replicated.sessionTime()) {
                            problems.add(e.sessionId() + ": database (state " + state + ", " + seconds
                                    + " s) differs from the cluster (" + replicated.status() + ", "
                                    + replicated.sessionTime() + " s)");
                        }
                    }
                }
            }
        }
        return new AckVerifier.Report(expected.size(), problems);
    }
}
