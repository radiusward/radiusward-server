/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

/**
 * The replicated accounting state: per-session progress, deduplication and housekeeping (ADR 0003, 0012).
 *
 * <p>Pure and deterministic: no I/O, no wall clock, no randomness — every input is an argument, time is the
 * cluster time of the log entry. Two instances fed the same calls end in the same state and the same
 * {@link #digest()}. Allocation-free in steady state.
 *
 * <table>
 *   <caption>Rules</caption>
 *   <tr><th>Event</th><th>Rule</th></tr>
 *   <tr><td>Start</td><td>same start key as the stored session → DUPLICATE; otherwise a new session instance
 *       → APPLIED</td></tr>
 *   <tr><td>Interim</td><td>progress equal → DUPLICATE, older → STALE, newer → APPLIED; unknown session →
 *       created implicitly; after Stop → STALE</td></tr>
 *   <tr><td>Stop</td><td>already stopped → DUPLICATE; otherwise APPLIED, kept as a tombstone</td></tr>
 *   <tr><td>Accounting-On/Off</td><td>exact-key window; when APPLIED all active sessions of the NAS stop</td></tr>
 *   <tr><td>other</td><td>exact-key window</td></tr>
 * </table>
 */
public final class AccountingStateMachine {

    /** Version of the state-machine behaviour, carried in snapshots (ADR 0005). */
    public static final int STATE_VERSION = 2; // 2: export sinks (Phase 3)

    public static final int STATUS_START = 1;
    public static final int STATUS_STOP = 2;
    public static final int STATUS_INTERIM = 3;
    public static final int STATUS_ACCOUNTING_ON = 7;
    public static final int STATUS_ACCOUNTING_OFF = 8;

    /** Event flag bits, matching the protocol's {@code EventFlags}. */
    public static final int FLAG_SESSION_TIME = 1;

    public static final int FLAG_EVENT_TIMESTAMP = 2;

    /**
     * Tunables.
     *
     * @param maxSessions capacity; new sessions beyond it are rejected
     * @param tombstoneMs how long a stopped session is kept to recognise retransmitted Stops
     * @param idleTimeoutMs sessions without any event for this long are removed (lost Stop)
     * @param exactKeyWindowMs how long exact keys are remembered
     */
    public record Settings(int maxSessions, long tombstoneMs, long idleTimeoutMs, long exactKeyWindowMs) {
        public static Settings defaults(int maxSessions) {
            return new Settings(maxSessions, 3_600_000L, 7_200_000L, 900_000L);
        }
    }

    private final Settings settings;
    private final SessionStore store = new SessionStore();
    private final ExactKeyWindow window = new ExactKeyWindow();
    private final ExportState export = new ExportState();
    private SessionListener sessionListener;

    private long applied;
    private long duplicates;
    private long stale;
    private long rejected;
    private long expired;
    private long digest;
    private boolean timerScheduled;

    public AccountingStateMachine(Settings settings) {
        this.settings = settings;
    }

    /**
     * Sessions closed without an event of their own: by Accounting-On/Off of their NAS, or removed after the idle
     * timeout (lost Stop). Called while the slot is still valid. Not part of the replicated state; the cluster
     * passes none, the exporter's replica uses it to export those sessions too.
     */
    public interface SessionListener {
        int CAUSE_NAS_RESTART = 1;
        int CAUSE_IDLE_TIMEOUT = 2;

        void onSessionClosed(int slot, int cause, long now);
    }

    public void sessionListener(SessionListener listener) {
        this.sessionListener = listener;
    }

    /**
     * Applies one accounting event.
     *
     * @param flags {@link #FLAG_SESSION_TIME} and/or {@link #FLAG_EVENT_TIMESTAMP}
     * @param now cluster time of the log entry in milliseconds
     * @return one of {@link Outcomes}
     */
    public int apply(
            long sessionHi,
            long sessionLo,
            long exactHi,
            long exactLo,
            int nasId,
            int statusType,
            int flags,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets,
            long now) {
        int outcome = switch (statusType) {
            case STATUS_START -> start(sessionHi, sessionLo, exactHi, exactLo, nasId, now);
            case STATUS_INTERIM ->
                interim(sessionHi, sessionLo, nasId, flags, sessionTime, eventTimestamp, inputOctets, outputOctets);
            case STATUS_STOP -> stop(sessionHi, sessionLo, nasId, now);
            case STATUS_ACCOUNTING_ON, STATUS_ACCOUNTING_OFF -> nasRestart(exactHi, exactLo, nasId, now);
            default -> exactOnly(exactHi, exactLo, now);
        };
        if (outcome == Outcomes.APPLIED) {
            int slot = statusType == STATUS_START || statusType == STATUS_INTERIM || statusType == STATUS_STOP
                    ? store.find(sessionHi, sessionLo)
                    : -1;
            if (slot >= 0) {
                store.statusType(slot, statusType);
                store.flags(slot, (byte) flags);
                store.sessionTime(slot, sessionTime);
                store.eventTimestamp(slot, eventTimestamp);
                store.inputOctets(slot, inputOctets);
                store.outputOctets(slot, outputOctets);
                store.lastSeen(slot, seconds(now));
            }
            applied++;
            digest = mix(
                    digest,
                    sessionHi ^ Long.rotateLeft(sessionLo, 17),
                    exactHi ^ exactLo,
                    ((long) statusType << 32) ^ sessionTime,
                    eventTimestamp ^ (inputOctets * 31) ^ outputOctets);
        } else if (outcome == Outcomes.DUPLICATE) {
            duplicates++;
        } else if (outcome == Outcomes.STALE) {
            stale++;
        } else {
            rejected++;
        }
        return outcome;
    }

    private int start(long hi, long lo, long exactHi, long exactLo, int nasId, long now) {
        int key = fold(exactHi, exactLo);
        int slot = store.find(hi, lo);
        if (slot < 0) {
            if (store.size() >= settings.maxSessions()) {
                return Outcomes.REJECTED_CAPACITY;
            }
            slot = store.insert(hi, lo, nasId, SessionStore.ACTIVE);
            store.startKey(slot, key);
            return Outcomes.APPLIED;
        }
        if (store.startKey(slot) == key) {
            return Outcomes.DUPLICATE;
        }
        // a new instance of the session id (e.g. NAS rebooted without Accounting-On): start over
        store.state(slot, SessionStore.ACTIVE);
        store.startKey(slot, key);
        store.tombstoneUntil(slot, 0);
        return Outcomes.APPLIED;
    }

    private int interim(
            long hi,
            long lo,
            int nasId,
            int flags,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets) {
        int slot = store.find(hi, lo);
        if (slot < 0) {
            if (store.size() >= settings.maxSessions()) {
                return Outcomes.REJECTED_CAPACITY;
            }
            store.insert(hi, lo, nasId, SessionStore.ACTIVE); // Start was lost: create implicitly
            return Outcomes.APPLIED;
        }
        if (store.state(slot) == SessionStore.STOPPED) {
            return Outcomes.STALE;
        }
        int c = compareProgress(slot, flags, sessionTime, eventTimestamp, inputOctets + outputOctets);
        return c > 0 ? Outcomes.APPLIED : c == 0 ? Outcomes.DUPLICATE : Outcomes.STALE;
    }

    private int stop(long hi, long lo, int nasId, long now) {
        int slot = store.find(hi, lo);
        int until = seconds(now + settings.tombstoneMs());
        if (slot < 0) {
            if (store.size() < settings.maxSessions()) {
                slot = store.insert(hi, lo, nasId, SessionStore.STOPPED);
                store.tombstoneUntil(slot, until);
            }
            return Outcomes.APPLIED; // a Stop is never rejected; over capacity it is applied without a tombstone
        }
        if (store.state(slot) == SessionStore.STOPPED) {
            return Outcomes.DUPLICATE;
        }
        store.state(slot, SessionStore.STOPPED);
        store.tombstoneUntil(slot, until);
        return Outcomes.APPLIED;
    }

    private int nasRestart(long exactHi, long exactLo, int nasId, long now) {
        int outcome = exactOnly(exactHi, exactLo, now);
        if (outcome == Outcomes.APPLIED) {
            int until = seconds(now + settings.tombstoneMs());
            for (int slot = store.firstOfNas(nasId); slot >= 0; slot = store.nextOfNas(slot)) {
                if (store.state(slot) == SessionStore.ACTIVE) {
                    store.state(slot, SessionStore.STOPPED);
                    store.tombstoneUntil(slot, until);
                    if (sessionListener != null) {
                        sessionListener.onSessionClosed(slot, SessionListener.CAUSE_NAS_RESTART, now);
                    }
                }
            }
        }
        return outcome;
    }

    private int exactOnly(long exactHi, long exactLo, long now) {
        long key = exactHi ^ Long.rotateLeft(exactLo, 32);
        if (window.contains(key, now)) {
            return Outcomes.DUPLICATE;
        }
        window.add(key, now + settings.exactKeyWindowMs());
        return Outcomes.APPLIED;
    }

    /**
     * Compares an incoming interim with the stored progress: session time, then event time, then octets. A
     * value the incoming event carries but the stored one lacks (e.g. a Start has no session time) counts
     * as 0 on the stored side, so the first interim after a Start is progress.
     */
    private int compareProgress(int slot, int flags, long sessionTime, long eventTimestamp, long totalOctets) {
        int stored = store.flags(slot);
        if ((flags & FLAG_SESSION_TIME) != 0) {
            long storedTime = (stored & FLAG_SESSION_TIME) != 0 ? store.sessionTime(slot) : 0;
            int c = Long.compare(sessionTime, storedTime);
            if (c != 0) {
                return c;
            }
        }
        if ((flags & FLAG_EVENT_TIMESTAMP) != 0 && (stored & FLAG_EVENT_TIMESTAMP) != 0) {
            int c = Long.compare(eventTimestamp, store.eventTimestamp(slot));
            if (c != 0) {
                return c;
            }
        }
        return Long.compare(totalOctets, store.inputOctets(slot) + store.outputOctets(slot));
    }

    /**
     * Housekeeping, run from a cluster timer: removes stopped sessions whose tombstone expired, idle active
     * sessions, and expired exact keys. Iterates slots in order, so it is deterministic.
     *
     * @return number of sessions removed
     */
    public int sweep(long now) {
        int nowSeconds = seconds(now);
        int idleBefore = seconds(now - settings.idleTimeoutMs());
        int removed = 0;
        for (int slot = 0, end = store.highWater(); slot < end; slot++) {
            byte state = store.state(slot);
            if ((state == SessionStore.STOPPED && store.tombstoneUntil(slot) <= nowSeconds)
                    || (state == SessionStore.ACTIVE && store.lastSeen(slot) <= idleBefore)) {
                if (state == SessionStore.ACTIVE) {
                    expired++;
                    if (sessionListener != null) {
                        sessionListener.onSessionClosed(slot, SessionListener.CAUSE_IDLE_TIMEOUT, now);
                    }
                }
                store.remove(slot);
                removed++;
            }
        }
        window.evict(now);
        if (removed > 0) {
            digest = mix(digest, removed, now, 0, 0);
        }
        return removed;
    }

    // ---- snapshot support --------------------------------------------------------------------------

    /** Restores one session from a snapshot. */
    public void restoreSession(
            long hi,
            long lo,
            int nasId,
            byte state,
            int statusType,
            int flags,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets,
            int startKey,
            int lastSeen,
            int tombstoneUntil) {
        int slot = store.insert(hi, lo, nasId, state);
        store.statusType(slot, statusType);
        store.flags(slot, (byte) flags);
        store.sessionTime(slot, sessionTime);
        store.eventTimestamp(slot, eventTimestamp);
        store.inputOctets(slot, inputOctets);
        store.outputOctets(slot, outputOctets);
        store.startKey(slot, startKey);
        store.lastSeen(slot, lastSeen);
        store.tombstoneUntil(slot, tombstoneUntil);
    }

    public void restoreExactKey(long key, long expiry) {
        window.add(key, expiry);
    }

    public void restoreCounters(
            long applied, long duplicates, long stale, long rejected, long digest, boolean timerScheduled) {
        this.applied = applied;
        this.duplicates = duplicates;
        this.stale = stale;
        this.rejected = rejected;
        this.digest = digest;
        this.timerScheduled = timerScheduled;
    }

    public SessionStore store() {
        return store;
    }

    /** Export checkpoints, leases and lag (ADR 0017). */
    public ExportState export() {
        return export;
    }

    /** Counts an event rejected before it reached {@link #apply} (export lag). */
    public void countRejected() {
        rejected++;
    }

    public ExactKeyWindow window() {
        return window;
    }

    // ---- accessors ---------------------------------------------------------------------------------

    public long applied() {
        return applied;
    }

    public long duplicates() {
        return duplicates;
    }

    public long stale() {
        return stale;
    }

    public long rejected() {
        return rejected;
    }

    /** Active sessions removed by the idle timeout. */
    public long expired() {
        return expired;
    }

    /** Running hash over every state change; equal on all replicas that applied the same log. */
    public long digest() {
        return digest;
    }

    public boolean timerScheduled() {
        return timerScheduled;
    }

    public void timerScheduled(boolean scheduled) {
        this.timerScheduled = scheduled;
    }

    public Settings settings() {
        return settings;
    }

    private static int seconds(long millis) {
        return (int) (millis / 1000);
    }

    private static int fold(long hi, long lo) {
        long x = hi ^ lo;
        int folded = (int) (x ^ (x >>> 32));
        return folded == 0 ? 1 : folded; // 0 means "no start seen"
    }

    private static long mix(long digest, long a, long b, long c, long d) {
        long h = digest;
        h = (h ^ a) * 0x9E37_79B9_7F4A_7C15L;
        h = (h ^ b) * 0xC2B2_AE3D_27D4_EB4FL;
        h = (h ^ c) * 0x1656_67B1_9E37_79F9L;
        h = (h ^ d) * 0x9E37_79B9_7F4A_7C15L;
        return Long.rotateLeft(h, 31) ^ (h >>> 29);
    }
}
