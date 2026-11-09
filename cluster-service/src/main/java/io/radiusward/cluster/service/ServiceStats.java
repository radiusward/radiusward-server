/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import java.util.concurrent.atomic.AtomicLongArray;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Counters the service thread publishes with release stores and the management thread reads (ADR 0013).
 * Writing is allocation-free; nothing here takes a lock.
 */
public final class ServiceStats {

    private static final int APPLIED = 0;
    private static final int DUPLICATES = 1;
    private static final int STALE = 2;
    private static final int REJECTED = 3;
    private static final int ACTIVE = 4;
    private static final int STOPPED = 5;
    private static final int DIGEST = 6;
    private static final int POSITION = 7;
    private static final int TERM = 8;
    private static final int LEADER = 9;
    private static final int SNAPSHOTS = 10;
    private static final int EGRESS_DROPPED = 11;
    private static final int MEMBER = 12;
    private static final int STARTED = 13;

    private static final int EXPORT_FLOOR = 14;
    private static final int EXPORT_LAG_REJECTED = 15;
    private static final int IDENTITY_MISMATCHES = 16;
    private static final int ACTIVE_VERSION = 17;
    private static final int LOWEST_SUPPORTED_VERSION = 18;
    private static final int VERSION_HELD = 19;

    private final AtomicLongArray values = new AtomicLongArray(20);
    /** Log position each member reported for itself; -1 = never reported (indexed by member id). */
    private final AtomicLongArray memberPositions = new AtomicLongArray(ExportState.MAX_MEMBERS);

    private final AtomicReference<String> role = new AtomicReference<>("UNKNOWN");
    private final AtomicReference<String> fatal = new AtomicReference<>();

    public ServiceStats() {
        values.set(LEADER, -1);
        values.set(MEMBER, -1);
        values.set(EXPORT_FLOOR, Long.MAX_VALUE);
        for (int m = 0; m < ExportState.MAX_MEMBERS; m++) {
            memberPositions.set(m, -1);
        }
    }

    /** Purge inputs from the replicated state (ADR 0014), published by the service thread. */
    void purgeInputs(ExportState export) {
        values.setRelease(EXPORT_FLOOR, export.slowestRequiredCheckpoint());
        for (int m = 0; m < ExportState.MAX_MEMBERS; m++) {
            memberPositions.setRelease(m, export.memberReported(m) ? export.memberPosition(m) : -1);
        }
    }

    void versions(int active, int lowestSupported, boolean held) {
        values.setRelease(ACTIVE_VERSION, active);
        values.setRelease(LOWEST_SUPPORTED_VERSION, lowestSupported);
        values.setRelease(VERSION_HELD, held ? 1 : 0);
    }

    /** State-machine version the cluster applies (ADR 0005). */
    public int activeVersion() {
        return (int) values.getAcquire(ACTIVE_VERSION);
    }

    /** Lowest version every member supports; 0 while a member has not reported. */
    public int lowestSupportedVersion() {
        return (int) values.getAcquire(LOWEST_SUPPORTED_VERSION);
    }

    /** Whether a member holds automatic activation. */
    public boolean versionHeld() {
        return values.getAcquire(VERSION_HELD) != 0;
    }

    void fatal(String reason) {
        fatal.set(reason);
    }

    /** Why this member's service stopped, {@code null} while it runs. */
    public String fatal() {
        return fatal.get();
    }

    void recordIdentityMismatch() {
        values.getAndIncrement(IDENTITY_MISMATCHES);
    }

    /**
     * Commands whose NAS entry carried another identity setting than the entry's first command seen by this member
     * (gateways configured differently, ADR 0019; since start).
     */
    public long identityMismatches() {
        return values.getAcquire(IDENTITY_MISMATCHES);
    }

    void recordExportLagRejection() {
        values.getAndIncrement(EXPORT_LAG_REJECTED);
    }

    /** Accounting this member rejected because a required sink was over its {@code maxLag} (since start). */
    public long exportLagRejections() {
        return values.getAcquire(EXPORT_LAG_REJECTED);
    }

    /** Lowest checkpoint of the sinks that hold the log, {@code Long.MAX_VALUE} without such sinks. */
    public long exportFloor() {
        return values.getAcquire(EXPORT_FLOOR);
    }

    /** Lowest log position reported by members {@code 0 .. memberCount-1}; 0 while one has never reported. */
    public long memberFloor(int memberCount) {
        long min = Long.MAX_VALUE;
        for (int m = 0; m < memberCount; m++) {
            long p = memberPositions.getAcquire(m);
            if (p < 0) {
                return 0;
            }
            min = Math.min(min, p);
        }
        return min == Long.MAX_VALUE ? 0 : min;
    }

    void update(
            long applied,
            long duplicates,
            long stale,
            long rejected,
            long active,
            long stopped,
            long digest,
            long position) {
        values.setRelease(APPLIED, applied);
        values.setRelease(DUPLICATES, duplicates);
        values.setRelease(STALE, stale);
        values.setRelease(REJECTED, rejected);
        values.setRelease(ACTIVE, active);
        values.setRelease(STOPPED, stopped);
        values.setRelease(DIGEST, digest);
        values.setRelease(POSITION, position);
        values.setRelease(STARTED, 1);
    }

    void leadership(long term, int leaderMemberId) {
        values.setRelease(TERM, term);
        values.setRelease(LEADER, leaderMemberId);
    }

    void memberId(int memberId) {
        values.setRelease(MEMBER, memberId);
    }

    void role(String newRole) {
        role.set(newRole);
    }

    void snapshotTaken() {
        values.getAndIncrement(SNAPSHOTS);
    }

    void recordEgressDropped() {
        values.getAndIncrement(EGRESS_DROPPED);
    }

    public String role() {
        return role.get();
    }

    public boolean started() {
        return values.getAcquire(STARTED) == 1;
    }

    public long applied() {
        return values.getAcquire(APPLIED);
    }

    public long duplicates() {
        return values.getAcquire(DUPLICATES);
    }

    public long stale() {
        return values.getAcquire(STALE);
    }

    public long rejected() {
        return values.getAcquire(REJECTED);
    }

    public long activeSessions() {
        return values.getAcquire(ACTIVE);
    }

    public long stoppedSessions() {
        return values.getAcquire(STOPPED);
    }

    public long digest() {
        return values.getAcquire(DIGEST);
    }

    public long lastPosition() {
        return values.getAcquire(POSITION);
    }

    public long term() {
        return values.getAcquire(TERM);
    }

    public int leaderMemberId() {
        return (int) values.getAcquire(LEADER);
    }

    public int memberId() {
        return (int) values.getAcquire(MEMBER);
    }

    public long snapshots() {
        return values.getAcquire(SNAPSHOTS);
    }

    public long egressDropped() {
        return values.getAcquire(EGRESS_DROPPED);
    }
}
