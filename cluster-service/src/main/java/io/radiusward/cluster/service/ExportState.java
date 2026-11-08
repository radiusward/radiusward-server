/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

/**
 * Per-sink export bookkeeping in the replicated state (ADR 0017): checkpoint, lease, lag and the lag policy.
 * Deterministic like the rest of the state machine: changed only by {@code ExportCheckpoint} entries and
 * evaluated with the log position and cluster time of the entry being applied.
 *
 * <p>Lease: one member exports a sink at a time. A checkpoint from the owner with the current epoch renews it;
 * a claim from anyone when the lease has expired, or from the owner with a stale epoch (its exporter
 * restarted), takes it over with a new epoch. Sinks fence writes with that epoch.
 *
 * <p>Lag by time is measured from {@code behindSince}: the cluster time of the first accounting entry the sink
 * had not exported after it was last fully caught up. So an idle period never counts as lag.
 */
public final class ExportState {

    public static final int MAX_SINKS = 16;
    public static final int NAME_LENGTH = 32;

    public static final int ON_MAX_LAG_BLOCK = 0;
    public static final int ON_MAX_LAG_DETACH = 1;

    public static final int GRANTED = 0;
    public static final int NOT_OWNER = 1;
    public static final int FULL = 2;

    private static final long NONE = Long.MIN_VALUE;

    private final String[] names = new String[MAX_SINKS];
    private final long[] checkpoint = new long[MAX_SINKS];
    private final int[] owner = new int[MAX_SINKS];
    private final long[] epoch = new long[MAX_SINKS];
    private final long[] leaseExpiry = new long[MAX_SINKS];
    private final long[] lastEventTime = new long[MAX_SINKS];
    private final long[] behindSince = new long[MAX_SINKS];
    private final boolean[] required = new boolean[MAX_SINKS];
    private final long[] maxLagBytes = new long[MAX_SINKS];
    private final long[] maxLagMs = new long[MAX_SINKS];
    private final int[] onMaxLag = new int[MAX_SINKS];
    private final boolean[] detached = new boolean[MAX_SINKS];
    /** Position a resync asked for, or -1; while set the exporter starts from the checkpoint. */
    private final long[] resyncFrom = new long[MAX_SINKS];

    private int count;
    private long lastCommandPosition;

    /** Highest member id + 1 that has reported; positions are indexed by member id. */
    public static final int MAX_MEMBERS = 16;

    private final long[] memberPosition = new long[MAX_MEMBERS];
    private final boolean[] memberReported = new boolean[MAX_MEMBERS];

    /**
     * Applies an {@code ExportCheckpoint}; returns {@link #GRANTED}, {@link #NOT_OWNER} or {@link #FULL}.
     * On {@link #GRANTED} the checkpoint only moves forward.
     */
    public int checkpoint(
            String name,
            int member,
            long claimedEpoch,
            long position,
            long eventTime,
            long leaseTimeoutMs,
            boolean isRequired,
            long lagBytesLimit,
            long lagMsLimit,
            int policy,
            long now) {
        int slot = find(name);
        if (slot < 0) {
            if (count == MAX_SINKS) {
                return FULL;
            }
            slot = count++;
            names[slot] = name;
            owner[slot] = -1;
            behindSince[slot] = NONE;
            resyncFrom[slot] = -1;
        }
        boolean leaseValid = owner[slot] >= 0 && now < leaseExpiry[slot];
        if (owner[slot] == member && claimedEpoch == epoch[slot] && leaseValid) {
            // renewal
        } else if (!leaseValid || owner[slot] == member) {
            owner[slot] = member; // takeover; the owner's own restarted exporter also gets a new epoch
            epoch[slot]++;
        } else {
            return NOT_OWNER;
        }
        leaseExpiry[slot] = now + leaseTimeoutMs;
        required[slot] = isRequired;
        maxLagBytes[slot] = lagBytesLimit;
        maxLagMs[slot] = lagMsLimit;
        onMaxLag[slot] = policy;
        if (resyncFrom[slot] >= 0 && position > resyncFrom[slot] && claimedEpoch == epoch[slot]) {
            resyncFrom[slot] = -1; // the new exporter has written past the resync point
        }
        if (position > checkpoint[slot] && (resyncFrom[slot] < 0 || claimedEpoch == epoch[slot])) {
            checkpoint[slot] = position;
            lastEventTime[slot] = eventTime;
        }
        if (checkpoint[slot] >= lastCommandPosition) {
            behindSince[slot] = NONE; // fully caught up
        }
        if (detached[slot] && !overLimit(slot, lastCommandPosition, now)) {
            detached[slot] = false; // caught up again before anything it needs was purged
        }
        return GRANTED;
    }

    /**
     * Called before an accounting entry at {@code position} is applied: records when sinks fall behind, detaches
     * optional sinks over their limit and returns whether a required sink over its limit blocks the entry.
     */
    public boolean blocks(long position, long now) {
        boolean block = false;
        for (int i = 0; i < count; i++) {
            if (behindSince[i] == NONE && checkpoint[i] < position) {
                behindSince[i] = now;
            }
            if (!overLimit(i, position, now)) {
                continue;
            }
            if (onMaxLag[i] == ON_MAX_LAG_BLOCK && required[i]) {
                block = true;
            } else if (onMaxLag[i] == ON_MAX_LAG_DETACH) {
                detached[i] = true;
            }
        }
        return block;
    }

    /**
     * {@code radiusward admin resync}: moves the sink's checkpoint to {@code position} (also backwards), frees the
     * lease with a new epoch (fencing the current exporter) and re-attaches the sink. The next exporter starts at
     * the checkpoint, ignoring the position the sink stored itself. Returns false for an unknown sink.
     */
    public boolean resync(String name, long position) {
        int slot = find(name);
        if (slot < 0) {
            return false;
        }
        checkpoint[slot] = Math.max(0, position);
        resyncFrom[slot] = checkpoint[slot];
        epoch[slot]++;
        owner[slot] = -1;
        leaseExpiry[slot] = 0;
        detached[slot] = false;
        behindSince[slot] = NONE;
        return true;
    }

    public long resyncFrom(int slot) {
        return resyncFrom[slot];
    }

    /** Records that an accounting entry at {@code position} was processed (applied or not). */
    public void commandProcessed(long position) {
        lastCommandPosition = position;
    }

    private boolean overLimit(int slot, long position, long now) {
        if (maxLagBytes[slot] > 0 && position - checkpoint[slot] > maxLagBytes[slot]) {
            return true;
        }
        return maxLagMs[slot] > 0 && behindSince[slot] != NONE && now - behindSince[slot] > maxLagMs[slot];
    }

    /** A member reported how far its own copy of the log reaches; positions only move forward. */
    public void memberPosition(int member, long position) {
        if (member < 0 || member >= MAX_MEMBERS) {
            return;
        }
        memberReported[member] = true;
        memberPosition[member] = Math.max(memberPosition[member], position);
    }

    /**
     * Lowest position reported by the members {@code 0 .. memberCount-1}; 0 while any of them has never
     * reported. A member that stops reporting holds the floor: its log is never purged out from under it.
     */
    public long memberFloor(int memberCount) {
        long min = Long.MAX_VALUE;
        for (int m = 0; m < memberCount && m < MAX_MEMBERS; m++) {
            if (!memberReported[m]) {
                return 0;
            }
            min = Math.min(min, memberPosition[m]);
        }
        return min == Long.MAX_VALUE ? 0 : min;
    }

    public boolean memberReported(int member) {
        return memberReported[member];
    }

    public long memberPosition(int member) {
        return memberPosition[member];
    }

    /** Lowest checkpoint of the sinks that hold the log (required and not detached), or {@code Long.MAX_VALUE}. */
    public long slowestRequiredCheckpoint() {
        long min = Long.MAX_VALUE;
        for (int i = 0; i < count; i++) {
            if (!detached[i]) {
                min = Math.min(min, checkpoint[i]);
            }
        }
        return min;
    }

    public int find(String name) {
        for (int i = 0; i < count; i++) {
            if (names[i].equals(name)) {
                return i;
            }
        }
        return -1;
    }

    public int count() {
        return count;
    }

    public String name(int slot) {
        return names[slot];
    }

    public long checkpoint(int slot) {
        return checkpoint[slot];
    }

    public int owner(int slot) {
        return owner[slot];
    }

    public long epoch(int slot) {
        return epoch[slot];
    }

    public long leaseExpiry(int slot) {
        return leaseExpiry[slot];
    }

    public long lastEventTime(int slot) {
        return lastEventTime[slot];
    }

    public long behindSince(int slot) {
        return behindSince[slot];
    }

    public boolean required(int slot) {
        return required[slot];
    }

    public long maxLagBytes(int slot) {
        return maxLagBytes[slot];
    }

    public long maxLagMs(int slot) {
        return maxLagMs[slot];
    }

    public int onMaxLag(int slot) {
        return onMaxLag[slot];
    }

    public boolean detached(int slot) {
        return detached[slot];
    }

    public long lastCommandPosition() {
        return lastCommandPosition;
    }

    /** Lag of a sink in bytes at the last accounting entry. */
    public long lagBytes(int slot) {
        return Math.max(0, lastCommandPosition - checkpoint[slot]);
    }

    /** Restores one sink from a snapshot (in the original order). */
    public void restore(
            String name,
            long checkpointPosition,
            int ownerMember,
            long leaseEpoch,
            long expiry,
            long eventTime,
            long behind,
            boolean isRequired,
            long lagBytesLimit,
            long lagMsLimit,
            int policy,
            boolean isDetached,
            long resync) {
        if (count == MAX_SINKS) {
            throw new IllegalStateException("snapshot has more than " + MAX_SINKS + " sinks");
        }
        int slot = count++;
        names[slot] = name;
        checkpoint[slot] = checkpointPosition;
        owner[slot] = ownerMember;
        epoch[slot] = leaseEpoch;
        leaseExpiry[slot] = expiry;
        lastEventTime[slot] = eventTime;
        behindSince[slot] = behind;
        required[slot] = isRequired;
        maxLagBytes[slot] = lagBytesLimit;
        maxLagMs[slot] = lagMsLimit;
        onMaxLag[slot] = policy;
        detached[slot] = isDetached;
        resyncFrom[slot] = resync;
    }

    public void restoreLastCommandPosition(long position) {
        lastCommandPosition = position;
    }
}
