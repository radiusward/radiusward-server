/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.radiusward.protocol.LeaseResult;

/** The decisions a {@link SinkRunner} takes, free of I/O so every path can be tested on its own. */
final class ExportDecisions {

    private ExportDecisions() {}

    /** What a lease renewal answer means for the exporter. */
    enum Renewal {
        /** no answer (election, timeout): keep going, step back only after a lease timeout */
        NO_ANSWER,
        /** still the owner: adopt the epoch in the answer */
        KEEP,
        /** another member holds the lease */
        LOST,
        /** an admin resync happened: restart from the cluster's checkpoint */
        RESYNC
    }

    static Renewal renewal(LeaseClient.Ack ack, long currentEpoch) {
        if (ack == null) {
            return Renewal.NO_ANSWER;
        }
        if (ack.result() != LeaseResult.GRANTED) {
            return Renewal.LOST;
        }
        if (ack.resync() && ack.epoch() != currentEpoch) {
            return Renewal.RESYNC;
        }
        return Renewal.KEEP;
    }

    /**
     * Where a new owner starts: normally the later of the cluster's checkpoint and the sink's own position; after a
     * resync the cluster's checkpoint (re-export from there).
     */
    static long startPosition(LeaseClient.Ack ack, long storedPosition) {
        return ack.resync() ? Math.max(ack.checkpoint(), 0) : Math.max(Math.max(ack.checkpoint(), storedPosition), 0);
    }

    /** What to write now. */
    enum Flush {
        NONE,
        /** the batch is full or has waited long enough */
        BATCH,
        /** nothing to write, but the log moved (checkpoints, timers): store the position, on the timer only */
        EMPTY
    }

    static Flush flush(int rows, int batchRows, long waitedNanos, long lingerNanos, boolean timer, boolean progress) {
        if (rows >= batchRows || (rows > 0 && waitedNanos >= lingerNanos)) {
            return Flush.BATCH;
        }
        if (timer && rows == 0 && progress) {
            return Flush.EMPTY;
        }
        return Flush.NONE;
    }

    /** Whether the lease must be considered lost: no successful renewal for a whole lease timeout. */
    static boolean leaseStale(long nowNanos, long lastRenewedNanos, long leaseTimeoutMs) {
        return nowNanos - lastRenewedNanos > leaseTimeoutMs * 1_000_000L;
    }
}
