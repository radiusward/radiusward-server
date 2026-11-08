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

    private final AtomicLongArray values = new AtomicLongArray(14);
    private final AtomicReference<String> role = new AtomicReference<>("UNKNOWN");

    public ServiceStats() {
        values.set(LEADER, -1);
        values.set(MEMBER, -1);
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
