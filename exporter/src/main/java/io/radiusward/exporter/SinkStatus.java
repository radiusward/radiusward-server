/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

/** What the management endpoints show about one sink on this member; written by its runner thread. */
public final class SinkStatus {

    private final String name;
    private final String type;
    private volatile boolean exporting;
    private volatile long epoch;
    private volatile long position;
    private volatile int leaseOwner = -1;
    private volatile long clusterCheckpoint;
    private volatile boolean detached;
    private volatile long rows;
    private volatile long batches;
    private volatile long lastBatchNanos;
    private volatile String lastError;

    SinkStatus(String name, String type) {
        this.name = name;
        this.type = type;
    }

    void owner(boolean exporting, long epoch, long position) {
        this.exporting = exporting;
        this.epoch = epoch;
        this.position = position;
    }

    void lease(int owner, long epoch, long checkpoint, boolean detached) {
        this.leaseOwner = owner;
        this.epoch = epoch;
        this.clusterCheckpoint = checkpoint;
        this.detached = detached;
    }

    void batchWritten(int rowCount, long nanos) {
        rows += rowCount;
        batches++;
        lastBatchNanos = nanos;
        lastError = null;
    }

    void error(String error) {
        lastError = error;
    }

    public String name() {
        return name;
    }

    public String type() {
        return type;
    }

    /** Whether this member holds the lease and exports the sink. */
    public boolean exporting() {
        return exporting;
    }

    public long epoch() {
        return epoch;
    }

    /** Log position durably written by this member (while exporting). */
    public long position() {
        return position;
    }

    public int leaseOwner() {
        return leaseOwner;
    }

    public long clusterCheckpoint() {
        return clusterCheckpoint;
    }

    public boolean detached() {
        return detached;
    }

    public long rows() {
        return rows;
    }

    public long batches() {
        return batches;
    }

    public long lastBatchNanos() {
        return lastBatchNanos;
    }

    public String lastError() {
        return lastError;
    }
}
