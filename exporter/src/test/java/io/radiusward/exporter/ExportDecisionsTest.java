/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import static io.radiusward.exporter.ExportDecisions.Flush.BATCH;
import static io.radiusward.exporter.ExportDecisions.Flush.EMPTY;
import static io.radiusward.exporter.ExportDecisions.Flush.NONE;
import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.protocol.LeaseResult;
import org.junit.jupiter.api.Test;

class ExportDecisionsTest {

    private static LeaseClient.Ack ack(LeaseResult result, long epoch, long checkpoint, boolean resync) {
        return new LeaseClient.Ack(result, 0, epoch, checkpoint, false, resync);
    }

    @Test
    void renewalAnswers() {
        assertThat(ExportDecisions.renewal(null, 3)).isEqualTo(ExportDecisions.Renewal.NO_ANSWER);
        assertThat(ExportDecisions.renewal(ack(LeaseResult.NOT_OWNER, 4, 0, false), 3))
                .isEqualTo(ExportDecisions.Renewal.LOST);
        assertThat(ExportDecisions.renewal(ack(LeaseResult.FULL, 0, 0, false), 3))
                .isEqualTo(ExportDecisions.Renewal.LOST);
        assertThat(ExportDecisions.renewal(ack(LeaseResult.GRANTED, 3, 0, false), 3))
                .isEqualTo(ExportDecisions.Renewal.KEEP);
        assertThat(ExportDecisions.renewal(ack(LeaseResult.GRANTED, 4, 0, false), 3))
                .as("new epoch without resync (own takeover after expiry): keep, adopt the epoch")
                .isEqualTo(ExportDecisions.Renewal.KEEP);
        assertThat(ExportDecisions.renewal(ack(LeaseResult.GRANTED, 4, 0, true), 3))
                .isEqualTo(ExportDecisions.Renewal.RESYNC);
        assertThat(ExportDecisions.renewal(ack(LeaseResult.GRANTED, 3, 0, true), 3))
                .as("resync already applied with this epoch")
                .isEqualTo(ExportDecisions.Renewal.KEEP);
    }

    @Test
    void startPositionPrefersTheLaterUnlessResyncing() {
        assertThat(ExportDecisions.startPosition(ack(LeaseResult.GRANTED, 1, 100, false), 250))
                .isEqualTo(250);
        assertThat(ExportDecisions.startPosition(ack(LeaseResult.GRANTED, 1, 300, false), 250))
                .isEqualTo(300);
        assertThat(ExportDecisions.startPosition(ack(LeaseResult.GRANTED, 1, 0, false), -1))
                .isZero();
        assertThat(ExportDecisions.startPosition(ack(LeaseResult.GRANTED, 2, 100, true), 250))
                .as("resync: the cluster's checkpoint wins")
                .isEqualTo(100);
    }

    @Test
    void flushWhenFullLingeredOrOnTheTimer() {
        long linger = 200_000_000L;
        assertThat(ExportDecisions.flush(5000, 5000, 0, linger, false, true)).isEqualTo(BATCH);
        assertThat(ExportDecisions.flush(10, 5000, linger, linger, false, true)).isEqualTo(BATCH);
        assertThat(ExportDecisions.flush(10, 5000, linger - 1, linger, true, true))
                .isEqualTo(NONE);
        assertThat(ExportDecisions.flush(0, 5000, 0, linger, true, true)).isEqualTo(EMPTY);
        assertThat(ExportDecisions.flush(0, 5000, 0, linger, false, true))
                .as("empty only on the timer")
                .isEqualTo(NONE);
        assertThat(ExportDecisions.flush(0, 5000, 0, linger, true, false))
                .as("nothing moved")
                .isEqualTo(NONE);
    }

    @Test
    void leaseStaleAfterATimeoutWithoutRenewal() {
        assertThat(ExportDecisions.leaseStale(10_000_000_000L, 0, 10_000)).isFalse();
        assertThat(ExportDecisions.leaseStale(10_000_000_001L, 0, 10_000)).isTrue();
    }
}
