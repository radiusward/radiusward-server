/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import io.radiusward.gateway.EventKeys;
import io.radiusward.protocol.SessionStatus;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Checks an acknowledgement log written by {@code radclient load --ack-log} against the replicated state: for
 * every session, the last acknowledged event must be in the cluster. The state may be newer (an event can be
 * committed without its ACK reaching the client), never older.
 */
public final class AckVerifier {

    /** The newest acknowledged event of one session. */
    public record Expected(String sessionId, int status, long sessionTime) {}

    /** Outcome; {@code lost} describes every session whose acknowledged event is missing. */
    public record Report(int sessions, List<String> lost) {
        public boolean ok() {
            return lost.isEmpty();
        }
    }

    /** Where the replicated sessions come from; {@link AdminClient#session} in production. */
    @FunctionalInterface
    public interface SessionLookup {
        AdminClient.Session session(long keyHi, long keyLo);
    }

    private static final int STOP = 2;

    private AckVerifier() {}

    /** Reads {@code session_id,status,session_time,acked,...} lines; later lines win at equal session time. */
    public static Map<String, Expected> lastAcknowledged(List<String> lines) {
        Map<String, Expected> last = new LinkedHashMap<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            String[] f = line.split(",");
            if (!f[3].equals("1")) {
                continue;
            }
            Expected e = new Expected(f[0], Integer.parseInt(f[1]), Long.parseLong(f[2]));
            Expected previous = last.get(e.sessionId());
            if (previous == null || e.sessionTime() >= previous.sessionTime()) {
                last.put(e.sessionId(), e);
            }
        }
        return last;
    }

    public static Report verify(Path ackLog, int nasId, SessionLookup lookup) throws IOException {
        Map<String, Expected> expected = lastAcknowledged(Files.readAllLines(ackLog, StandardCharsets.UTF_8));
        EventKeys keys = new EventKeys();
        List<String> lost = new ArrayList<>();
        for (Expected e : expected.values()) {
            UnsafeBuffer id = new UnsafeBuffer(e.sessionId().getBytes(StandardCharsets.US_ASCII));
            keys.compute(nasId, 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
            AdminClient.Session s = lookup.session(keys.sessionHi(), keys.sessionLo());
            String problem = check(e, s);
            if (problem != null) {
                lost.add(e.sessionId() + ": " + problem);
            }
        }
        return new Report(expected.size(), lost);
    }

    static String check(Expected e, AdminClient.Session s) {
        if (s.status() == SessionStatus.UNKNOWN || s.status() == SessionStatus.NULL_VAL) {
            return "missing (acknowledged status " + e.status() + " at " + e.sessionTime() + " s)";
        }
        if (s.sessionTime() < e.sessionTime()) {
            return "session time " + s.sessionTime() + " < acknowledged " + e.sessionTime();
        }
        if (e.status() == STOP && s.status() != SessionStatus.STOPPED) {
            return "acknowledged Stop, cluster has " + s.status();
        }
        return null;
    }
}
