/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

/**
 * Which state-machine behaviour the cluster applies (ADR 0005), as replicated state.
 *
 * <p>Code knows behaviours up to its {@link #supportedHere() supported} version; the cluster applies its <b>active</b>
 * version, which only a log entry changes: every member reports the version its code supports (with
 * {@code MemberLogPosition}), and once all members of the cluster support a newer one and none holds, the report that
 * completes the set activates it — or an {@code ActivateVersion} request does. Entries before that position are
 * applied, on every replay, with the version active then. Deterministic: only log content decides.
 *
 * <p>A member whose code is older than the active version cannot apply the log: {@link #requireSupported} fails.
 */
public final class StateVersions {

    /** The behaviour of the first release; applied while no version was ever activated. */
    public static final int BASELINE = 5;

    public static final int ACTIVATED = 0;
    public static final int NOT_NEWER = 1;
    public static final int MEMBERS_NOT_READY = 2;

    private final int supportedHere;
    private int active; // 0: never activated, BASELINE applies
    private int clusterSize;
    private final int[] supported = new int[ExportState.MAX_MEMBERS]; // 0: not reported
    private final boolean[] hold = new boolean[ExportState.MAX_MEMBERS];

    public StateVersions(int supportedHere) {
        this.supportedHere = supportedHere;
    }

    /** The version applied now. */
    public int active() {
        return active == 0 ? BASELINE : active;
    }

    /** Whether behaviour introduced in {@code version} applies. */
    public boolean atLeast(int version) {
        return active() >= version;
    }

    /** Newest version this member's code knows. */
    public int supportedHere() {
        return supportedHere;
    }

    /**
     * Records a member's report.
     *
     * @return the version this report activated, 0 if none
     */
    public int report(int member, int supportedVersion, int size, boolean holds) {
        if (member < 0 || member >= supported.length || size <= 0 || size > supported.length) {
            return 0;
        }
        supported[member] = supportedVersion;
        hold[member] = holds;
        clusterSize = size;
        int lowest = lowestSupported();
        if (lowest > active() && !held()) {
            active = lowest;
            return lowest;
        }
        return 0;
    }

    /** Explicit activation ({@code admin activate-version}); one of {@link #ACTIVATED}, {@link #NOT_NEWER}, …. */
    public int activate(int version) {
        if (version <= active()) {
            return NOT_NEWER;
        }
        if (lowestSupported() < version) {
            return MEMBERS_NOT_READY;
        }
        active = version;
        return ACTIVATED;
    }

    /** Lowest version all members of the cluster reported, 0 while one has not reported. */
    public int lowestSupported() {
        if (clusterSize == 0) {
            return 0;
        }
        int lowest = Integer.MAX_VALUE;
        for (int m = 0; m < clusterSize; m++) {
            if (supported[m] == 0) {
                return 0;
            }
            lowest = Math.min(lowest, supported[m]);
        }
        return lowest;
    }

    /** Whether a member holds automatic activation ({@code cluster.version.hold}). */
    public boolean held() {
        for (int m = 0; m < clusterSize; m++) {
            if (hold[m]) {
                return true;
            }
        }
        return false;
    }

    /** Fails when this member's code is older than the active version: it would apply entries wrongly. */
    public void requireSupported() {
        if (active() > supportedHere) {
            throw new UnsupportedStateVersionException(active(), supportedHere);
        }
    }

    // ---- snapshot ----------------------------------------------------------------------------------

    /** The raw active version, 0 if never activated. */
    public int activeRaw() {
        return active;
    }

    public int clusterSize() {
        return clusterSize;
    }

    public int supported(int member) {
        return supported[member];
    }

    public boolean hold(int member) {
        return hold[member];
    }

    public void restore(int activeRaw, int size) {
        this.active = activeRaw;
        this.clusterSize = size;
    }

    public void restoreMember(int member, int supportedVersion, boolean holds) {
        if (member >= 0 && member < supported.length) {
            supported[member] = supportedVersion;
            hold[member] = holds;
        }
    }

    /** The cluster activated a version this member's code does not know. */
    public static final class UnsupportedStateVersionException extends IllegalStateException {
        UnsupportedStateVersionException(int active, int supported) {
            super("the cluster applies state version " + active + ", this member's code supports up to " + supported
                    + ": run a release that supports it (ADR 0005)");
        }
    }
}
