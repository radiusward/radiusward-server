/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import io.radiusward.gateway.EventKeys;
import java.io.IOException;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * {@code radiusward admin verify-export}: every session of an acknowledgement log ({@code radclient load
 * --ack-log}) must be in the database's {@code accounting_session} with at least the acknowledged progress, and
 * stopped if its Stop was acknowledged. With a cluster connection the row must equal the replicated session.
 */
public final class ExportVerifier {

    private ExportVerifier() {}

    public static AckVerifier.Report verify(Path ackLog, int nasId, Connection db, AckVerifier.SessionLookup cluster)
            throws IOException, SQLException {
        return verify(ackLog, nasId, false, db, cluster);
    }

    /** As above; {@code byDevice}: the NAS entry identifies devices by NAS-Identifier (ADR 0019). */
    public static AckVerifier.Report verify(
            Path ackLog, int nasId, boolean byDevice, Connection db, AckVerifier.SessionLookup cluster)
            throws IOException, SQLException {
        Map<String, AckVerifier.Expected> expected = AckVerifier.lastAcknowledged(ackLog);
        EventKeys keys = new EventKeys();
        List<String> problems = new ArrayList<>();
        try (PreparedStatement ps =
                db.prepareStatement("SELECT state, session_seconds FROM accounting_session WHERE session_key = ?")) {
            for (AckVerifier.Expected e : expected.values()) {
                AckVerifier.sessionKey(keys, nasId, byDevice, e);
                ps.setObject(1, new UUID(keys.sessionHi(), keys.sessionLo()));
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        problems.add(e.name() + ": not in accounting_session");
                        continue;
                    }
                    int state = rs.getInt(1);
                    long seconds = rs.getLong(2);
                    if (seconds < e.sessionTime()) {
                        problems.add(e.name() + ": session_seconds " + seconds + " < acknowledged " + e.sessionTime());
                    } else if (e.status() == 2 && state != 2) {
                        problems.add(e.name() + ": acknowledged Stop, database has an active session");
                    } else if (cluster != null) {
                        AdminClient.Session replicated = cluster.session(keys.sessionHi(), keys.sessionLo());
                        boolean stopped = replicated.status() == io.radiusward.protocol.SessionStatus.STOPPED;
                        if ((state == 2) != stopped || seconds != replicated.sessionTime()) {
                            problems.add(e.name() + ": database (state " + state + ", " + seconds
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
