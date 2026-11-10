/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import org.agrona.DirectBuffer;

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
 *   <tr><td>Start</td><td>unknown session → APPLIED; same start key as the stored session → DUPLICATE; a late
 *       Start (see {@link #isLateStart}) → MERGED for an active session, STALE for a stopped one; otherwise a new
 *       session instance → APPLIED</td></tr>
 *   <tr><td>Interim</td><td>progress equal → DUPLICATE, older → STALE, newer → APPLIED; unknown session →
 *       created implicitly, unless its Event-Timestamp is older than the tombstone window → STALE; after Stop →
 *       STALE</td></tr>
 *   <tr><td>Stop</td><td>already stopped → DUPLICATE; otherwise APPLIED, kept as a tombstone</td></tr>
 *   <tr><td>Accounting-On/Off</td><td>exact-key window; when APPLIED all active sessions of the NAS (the device
 *       scope, ADR 0019) stop — none when the device is unknown</td></tr>
 *   <tr><td>other</td><td>exact-key window</td></tr>
 *   <tr><td>AuthReservation (v6)</td><td>see {@link #reserve}</td></tr>
 * </table>
 *
 * <p>From state version 6 an applied event also records the session's user and device (simultaneous use, ADR 0023);
 * a session newly online for its user ends a reservation the user held. From state version 7 it also keeps the
 * attributes that name the session to its NAS and the time of its first event (CoA and Disconnect, ADR 0036).
 */
public final class AccountingStateMachine {

    /**
     * Newest behaviour this code knows (ADR 0005); the cluster applies {@link StateVersions#active()}. History before
     * the first release (no gate yet): 2 export sinks, 3 late Start merged, 4 old Interim stale, 5 idle timeout per
     * NAS entry = {@link StateVersions#BASELINE}. From 6 on, new rules check {@link #atLeast(int)}: 6 users and
     * devices of sessions, {@code AuthReservation} (simultaneous use); 7 identifying attributes and first event of
     * sessions.
     */
    public static final int STATE_VERSION = 8;

    /** {@link #reserve} results, matching the protocol's {@code ReservationResult}. */
    public static final int RESERVATION_GRANTED = 0;

    public static final int RESERVATION_DENIED = 1;
    public static final int RESERVATION_UNSUPPORTED = 2;
    public static final int RESERVATION_CAPACITY = 3;

    public static final int STATUS_START = 1;
    public static final int STATUS_STOP = 2;
    public static final int STATUS_INTERIM = 3;
    public static final int STATUS_ACCOUNTING_ON = 7;
    public static final int STATUS_ACCOUNTING_OFF = 8;

    /** Event flag bits, matching the protocol's {@code EventFlags}. */
    public static final int FLAG_SESSION_TIME = 1;

    public static final int FLAG_EVENT_TIMESTAMP = 2;

    /**
     * The NAS entry identifies devices by attribute, but this request carried none (ADR 0019): an Accounting-On/Off
     * then stops no session, since its device is unknown. Not stored with sessions.
     */
    public static final int FLAG_DEVICE_UNKNOWN = 4;

    private static final int STORED_FLAGS = FLAG_SESSION_TIME | FLAG_EVENT_TIMESTAMP;

    /**
     * Tunables.
     *
     * @param maxSessions capacity; new sessions beyond it are rejected
     * @param tombstoneMs how long a stopped session is kept to recognise retransmitted Stops
     * @param idleTimeoutMs sessions without any event for this long are removed (lost Stop)
     * @param exactKeyWindowMs how long exact keys are remembered
     * @param supportedVersion newest state version this code applies ({@link #STATE_VERSION}; lower or higher only in
     *     tests of upgrades, {@code debug.state.version.supported})
     * @param maxReservations reservations held at once; beyond it a request is answered {@code CAPACITY}. Like
     *     {@code maxSessions}, equal on every member.
     * @param maxSubscribers SIM subscribers with a sequence number (state version 8, ADR 0061); beyond it a new one is
     *     answered {@code CAPACITY}. Equal on every member.
     */
    public record Settings(
            int maxSessions,
            long tombstoneMs,
            long idleTimeoutMs,
            long exactKeyWindowMs,
            int supportedVersion,
            int maxReservations,
            int maxSubscribers) {

        public static final int DEFAULT_MAX_RESERVATIONS = 65_536;
        public static final int DEFAULT_MAX_SUBSCRIBERS = 100_000;

        public Settings(
                int maxSessions,
                long tombstoneMs,
                long idleTimeoutMs,
                long exactKeyWindowMs,
                int supportedVersion,
                int maxReservations) {
            this(
                    maxSessions,
                    tombstoneMs,
                    idleTimeoutMs,
                    exactKeyWindowMs,
                    supportedVersion,
                    maxReservations,
                    DEFAULT_MAX_SUBSCRIBERS);
        }

        public Settings(
                int maxSessions, long tombstoneMs, long idleTimeoutMs, long exactKeyWindowMs, int supportedVersion) {
            this(maxSessions, tombstoneMs, idleTimeoutMs, exactKeyWindowMs, supportedVersion, DEFAULT_MAX_RESERVATIONS);
        }

        public Settings(int maxSessions, long tombstoneMs, long idleTimeoutMs, long exactKeyWindowMs) {
            this(maxSessions, tombstoneMs, idleTimeoutMs, exactKeyWindowMs, STATE_VERSION);
        }

        public static Settings defaults(int maxSessions) {
            return new Settings(maxSessions, 3_600_000L, 7_200_000L, 900_000L);
        }
    }

    private final Settings settings;
    private final SessionStore store = new SessionStore();
    private final ExactKeyWindow window = new ExactKeyWindow();
    private final ExportState export = new ExportState();
    private final StateVersions versions;
    private final Reservations reservations;
    /** The last SQN handed out per SIM subscriber (state version 8, ADR 0061); -1 = none. */
    private final org.agrona.collections.Long2LongHashMap sqns = new org.agrona.collections.Long2LongHashMap(-1);

    private SessionListener sessionListener;

    private long applied;
    private long duplicates;
    private long stale;
    private long rejected;
    private long expired;
    private long digest;
    private boolean timerScheduled;
    private boolean created;

    public AccountingStateMachine(Settings settings) {
        this(settings, settings.supportedVersion());
    }

    /** With code supporting state versions up to {@code supportedVersion} (tests of upgrades). */
    public AccountingStateMachine(Settings settings, int supportedVersion) {
        this.settings = settings;
        this.versions = new StateVersions(supportedVersion);
        this.reservations = new Reservations(settings.maxReservations());
    }

    /** Whether behaviour introduced in state version {@code version} applies at this log position. */
    public boolean atLeast(int version) {
        return versions.atLeast(version);
    }

    /** Replicated state versions. */
    public StateVersions versions() {
        return versions;
    }

    /**
     * Applies a member's {@code MemberLogPosition} report of its supported version.
     *
     * @return the version it activated, 0 if none
     * @throws StateVersions.UnsupportedStateVersionException if this member's code cannot apply what was activated
     */
    public int reportMemberVersion(int member, int supportedVersion, int clusterSize, boolean hold) {
        int activated = versions.report(member, supportedVersion, clusterSize, hold);
        if (activated != 0) {
            digest = mix(digest, 0x5ec7_0b51L, activated, 0, 0);
            versions.requireSupported();
        }
        return activated;
    }

    /** Applies an {@code ActivateVersion} request; returns a {@link StateVersions} result. */
    public int activateVersion(int version) {
        int result = versions.activate(version);
        if (result == StateVersions.ACTIVATED) {
            digest = mix(digest, 0x5ec7_0b51L, version, 0, 0);
            versions.requireSupported();
        }
        return result;
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
        return apply(
                sessionHi,
                sessionLo,
                exactHi,
                exactLo,
                nasId,
                statusType,
                flags,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                0,
                now);
    }

    /**
     * As above, with the idle timeout of the event's NAS entry.
     *
     * @param idleMinutes remove the session after this many minutes without an event ({@code nas.<name>.idle.timeout});
     *     0 = {@link Settings#idleTimeoutMs()}. The latest applied event of the session sets it.
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
            int idleMinutes,
            long now) {
        return apply(
                sessionHi,
                sessionLo,
                exactHi,
                exactLo,
                nasId,
                statusType,
                flags,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                idleMinutes,
                0,
                0,
                now);
    }

    /**
     * As above, with the user and device of the event (protocol version 6). They are recorded only from state version
     * 6 on ({@link #atLeast(int)}); before that they are ignored, as by older code.
     *
     * @param userKey hash of the User-Name, 0 = none
     * @param deviceKey the Calling-Station-Id as a key, 0 = none
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
            int idleMinutes,
            long userKey,
            long deviceKey,
            long now) {
        return apply(
                sessionHi,
                sessionLo,
                exactHi,
                exactLo,
                nasId,
                statusType,
                flags,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                idleMinutes,
                userKey,
                deviceKey,
                null,
                0,
                0,
                now);
    }

    /**
     * As above, with the attributes that name the session to its NAS ({@link SessionIdentity}); kept from state
     * version 7 on ({@link #atLeast(int)}), replaced by every applied event of the session.
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
            int idleMinutes,
            long userKey,
            long deviceKey,
            DirectBuffer identity,
            int identityOffset,
            int identityLength,
            long now) {
        created = false;
        int outcome = switch (statusType) {
            case STATUS_START -> start(sessionHi, sessionLo, exactHi, exactLo, nasId, flags, eventTimestamp, now);
            case STATUS_INTERIM ->
                interim(
                        sessionHi,
                        sessionLo,
                        nasId,
                        flags,
                        sessionTime,
                        eventTimestamp,
                        inputOctets,
                        outputOctets,
                        now);
            case STATUS_STOP -> stop(sessionHi, sessionLo, nasId, now);
            case STATUS_ACCOUNTING_ON, STATUS_ACCOUNTING_OFF ->
                nasRestart(exactHi, exactLo, nasId, (flags & FLAG_DEVICE_UNKNOWN) == 0, now);
            default -> exactOnly(exactHi, exactLo, now);
        };
        if (outcome == Outcomes.APPLIED || outcome == Outcomes.MERGED) {
            int slot = statusType == STATUS_START || statusType == STATUS_INTERIM || statusType == STATUS_STOP
                    ? store.find(sessionHi, sessionLo)
                    : -1;
            if (slot >= 0) {
                store.idleMinutes(slot, idleMinutes);
            }
            if (slot >= 0 && outcome == Outcomes.APPLIED) { // a late Start (MERGED) keeps the session's progress
                store.statusType(slot, statusType);
                store.flags(slot, (byte) (flags & STORED_FLAGS));
                store.sessionTime(slot, sessionTime);
                store.eventTimestamp(slot, eventTimestamp);
                store.inputOctets(slot, inputOctets);
                store.outputOctets(slot, outputOctets);
                store.lastSeen(slot, seconds(now));
            }
            if (slot >= 0 && atLeast(7) && memberState) {
                if (store.firstSeen(slot) == 0) {
                    store.firstSeen(slot, seconds(now));
                }
                if (identityLength > 0 && memberState) {
                    store.identity(slot, identity, identityOffset, identityLength);
                }
                digest = mix(digest, 0x1d_0007L, store.identityHash(slot), store.firstSeen(slot), sessionHi);
            }
            if (slot >= 0 && userKey != 0 && atLeast(6) && memberState) {
                if (store.user(slot, userKey, deviceKey)) {
                    reservations.consume(userKey, deviceKey, now); // the device came online: its place is taken
                }
                digest = mix(digest, 0x05e7_0001L, userKey, deviceKey, store.state(slot));
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

    private int start(
            long hi, long lo, long exactHi, long exactLo, int nasId, int flags, long eventTimestamp, long now) {
        int key = fold(exactHi, exactLo);
        int slot = store.find(hi, lo);
        if (slot < 0) {
            if (store.size() >= settings.maxSessions()) {
                return Outcomes.REJECTED_CAPACITY;
            }
            slot = store.insert(hi, lo, nasId, SessionStore.ACTIVE);
            store.startKey(slot, key);
            created = true;
            return Outcomes.APPLIED;
        }
        if (store.startKey(slot) == key) {
            return Outcomes.DUPLICATE;
        }
        if (isLateStart(slot, flags, eventTimestamp)) {
            if (store.state(slot) == SessionStore.STOPPED) {
                return Outcomes.STALE; // the session is already closed; a late Start must not reopen it
            }
            store.startKey(slot, key); // retransmissions of this Start are duplicates from now on
            store.lastSeen(slot, seconds(now));
            return Outcomes.MERGED;
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
            long outputOctets,
            long now) {
        int slot = store.find(hi, lo);
        if (slot < 0) {
            if (olderThanTombstones(flags, eventTimestamp, now)) {
                // the session may have stopped and been forgotten since: never bring it back from an old Interim
                return Outcomes.STALE;
            }
            if (store.size() >= settings.maxSessions()) {
                return Outcomes.REJECTED_CAPACITY;
            }
            store.insert(hi, lo, nasId, SessionStore.ACTIVE); // Start lost or not yet here: create implicitly
            created = true;
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
                created = true;
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

    private int nasRestart(long exactHi, long exactLo, int nasId, boolean deviceKnown, long now) {
        int outcome = exactOnly(exactHi, exactLo, now);
        // a device behind NAT without identity: stopping the whole entry would stop every other device's sessions
        if (outcome == Outcomes.APPLIED && deviceKnown) {
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
     * Whether an event's Event-Timestamp (seconds) lies further back than the tombstone window before the cluster
     * time {@code now}: a session it belonged to may have stopped and been removed with its tombstone since, so the
     * event cannot be judged. Without an Event-Timestamp nothing is known and it is not old.
     */
    private boolean olderThanTombstones(int flags, long eventTimestamp, long now) {
        return (flags & FLAG_EVENT_TIMESTAMP) != 0 && eventTimestamp * 1000 < now - settings.tombstoneMs();
    }

    /**
     * Whether a Start with a new start key belongs to the stored session instance and only arrived late (after its
     * Interim or Stop), rather than starting a new instance of the session id (NAS rebooted without
     * Accounting-On). With an Event-Timestamp on both sides the Start is late when it is not newer than the
     * session's last event. Without one, only a session that never saw a Start (created by an Interim) and is
     * still active takes it as its late Start; a stopped session is started over, as before.
     */
    private boolean isLateStart(int slot, int flags, long eventTimestamp) {
        if ((flags & FLAG_EVENT_TIMESTAMP) != 0 && (store.flags(slot) & FLAG_EVENT_TIMESTAMP) != 0) {
            return eventTimestamp <= store.eventTimestamp(slot);
        }
        return store.startKey(slot) == 0 && store.state(slot) == SessionStore.ACTIVE;
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
     * Whether the user may bring another device online ({@code AuthReservation}, state version 6). Devices count once
     * however many sessions they have; a session without a device counts on its own.
     *
     * <ul>
     *   <li>before state version 6 is active → {@link #RESERVATION_UNSUPPORTED}, nothing changes
     *   <li>the device is already online, or holds a live reservation (then extended) → {@link #RESERVATION_GRANTED}
     *   <li>devices online plus other live reservations reach {@code maxDevices} → {@link #RESERVATION_DENIED}
     *   <li>otherwise a reservation until {@code now + ttlMs} → {@link #RESERVATION_GRANTED}, or
     *       {@link #RESERVATION_CAPACITY} if none fits
     * </ul>
     *
     * @param ttlMs how long the reservation waits for the device's Accounting-Start; from the log entry, so equal on
     *     every member
     */
    public int reserve(long userKey, long deviceKey, int maxDevices, long ttlMs, long now) {
        if (!atLeast(6)) {
            return RESERVATION_UNSUPPORTED;
        }
        int result;
        long expiry = now + ttlMs;
        if (userKey == 0) {
            result = RESERVATION_DENIED; // no user to count against
        } else if (store.online(userKey, deviceKey)) {
            result = RESERVATION_GRANTED; // the same device again (reconnect, roaming)
        } else if (deviceKey != 0 && reservations.refresh(userKey, deviceKey, expiry, now)) {
            result = RESERVATION_GRANTED; // a retransmission or a second attempt of the same device
        } else if (store.devicesOnline(userKey, maxDevices) + reservations.live(userKey, now, store) >= maxDevices) {
            result = RESERVATION_DENIED;
        } else {
            result = reservations.add(userKey, deviceKey, expiry) ? RESERVATION_GRANTED : RESERVATION_CAPACITY;
        }
        digest = mix(digest, 0x05e7_0002L, userKey, deviceKey, ((long) maxDevices << 8) | result);
        return result;
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
            int idle = store.idleMinutes(slot);
            int before = idle == 0 ? idleBefore : nowSeconds - idle * 60; // per NAS entry, else the default
            if ((state == SessionStore.STOPPED && store.tombstoneUntil(slot) <= nowSeconds)
                    || (state == SessionStore.ACTIVE && store.lastSeen(slot) <= before)) {
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
        int ended = reservations.sweep(now);
        if (ended > 0) {
            digest = mix(digest, 0x05e7_0003L, ended, now, 0);
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
        restoreSession(
                hi,
                lo,
                nasId,
                state,
                statusType,
                flags,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                startKey,
                lastSeen,
                tombstoneUntil,
                0);
    }

    /** Restores one session from a snapshot, with its NAS entry's idle timeout (minutes, 0 = default). */
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
            int tombstoneUntil,
            int idleMinutes) {
        int slot = store.insert(hi, lo, nasId, state);
        store.idleMinutes(slot, idleMinutes);
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

    /** Sets a restored session's user and device (snapshot version 6). */
    public void restoreUser(long hi, long lo, long userKey, long deviceKey) {
        int slot = store.find(hi, lo);
        if (slot >= 0 && userKey != 0 && memberState) {
            store.user(slot, userKey, deviceKey);
        }
    }

    private boolean memberState = true;

    /**
     * Whether sessions keep what only a member's answers need (ADR 0036): their users and devices (simultaneous use,
     * ADR 0023) and identifying attributes (CoA). The exporter's replica does not: export outcomes never depend on
     * them, and the replica lives in the member's JVM. Only this machine's own digest is affected.
     */
    public void memberState(boolean keep) {
        this.memberState = keep;
    }

    /** Sets a restored session's first event and identifying attributes (snapshot version 7). */
    public void restoreIdentity(long hi, long lo, int firstSeen, DirectBuffer identity, int offset, int length) {
        int slot = store.find(hi, lo);
        if (slot >= 0) {
            if (!memberState) {
                return;
            }
            store.firstSeen(slot, firstSeen);
            if (length > 0 && length < SessionStore.IDENTITY_SIZE) {
                store.identity(slot, identity, offset, length);
            }
        }
    }

    /** {@link #nextSqn} result: state version 8 is not active yet. */
    public static final long SQN_UNSUPPORTED = -1;

    /** {@link #nextSqn} result: no room for another subscriber. */
    public static final long SQN_CAPACITY = -2;

    private static final long SQN_MAX = (1L << 48) - 1;

    /**
     * The next sequence number of a SIM subscriber for an EAP-AKA challenge (state version 8, ADR 0061): the next SEQ
     * above both the last one handed out and {@code floor}, with IND = 0 (3GPP TS 33.102 Annex C: SQN = SEQ ‖ IND, IND
     * of 5 bits). {@code floor} is the store's {@code SIM-SQN}, or after a resynchronisation the SQN the USIM reported,
     * so the next challenge is fresh to it. Every member hands out the same numbers: the log decides.
     *
     * @return the SQN (48 bits), {@link #SQN_UNSUPPORTED} or {@link #SQN_CAPACITY}
     */
    public long nextSqn(long subscriberKey, long floor) {
        if (!atLeast(8)) {
            return SQN_UNSUPPORTED;
        }
        long last = sqns.get(subscriberKey);
        if (last == -1 && sqns.size() >= settings.maxSubscribers()) {
            return SQN_CAPACITY;
        }
        long base = Math.max(last, Math.max(0, Math.min(floor, SQN_MAX)));
        long next = Math.min(((base >>> 5) + 1) << 5, SQN_MAX & ~31L);
        sqns.put(subscriberKey, next);
        digest = mix(digest, 0x5_19_0008L, subscriberKey, next, 0);
        return next;
    }

    /** The last SQN of a subscriber, -1 if none (tests, the snapshot). */
    public long sqn(long subscriberKey) {
        return sqns.get(subscriberKey);
    }

    public org.agrona.collections.Long2LongHashMap sqns() {
        return sqns;
    }

    /** From a snapshot. */
    public void restoreSqn(long subscriberKey, long sqn) {
        sqns.put(subscriberKey, sqn);
    }

    public void restoreReservation(long userKey, long deviceKey, long expiry) {
        reservations.restore(userKey, deviceKey, expiry);
    }

    /** Places held for devices granted under a simultaneous-use limit (state version 6). */
    public Reservations reservations() {
        return reservations;
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

    /**
     * Whether the last {@link #apply} created the session; for an Interim or Stop that means its Start was lost or
     * has not arrived yet. Not replicated state: valid only right after the call.
     */
    public boolean lastCreated() {
        return created;
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
