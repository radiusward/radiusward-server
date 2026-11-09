/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.protocol.AuthReservationDecoder;
import io.radiusward.protocol.MessageHeaderDecoder;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/** The worker side of reservations, with the cluster client played by the test. */
class ClusterReservationsTest {

    private final ClusterReservations reservations =
            new ClusterReservations(4, 7, Duration.ofMillis(300), Duration.ofSeconds(45));
    private final List<AuthReservationDecoder> seen = new ArrayList<>();

    /** Reads the requests like the cluster client and answers each with {@code result}. */
    private void answerAll(int result) {
        MessageHeaderDecoder header = new MessageHeaderDecoder();
        reservations.requests().read((type, buffer, index, length) -> {
            AuthReservationDecoder d = new AuthReservationDecoder();
            d.wrapAndApplyHeader(buffer, index, header);
            AuthReservationDecoder copy = new AuthReservationDecoder();
            byte[] bytes = new byte[length];
            buffer.getBytes(index, bytes);
            copy.wrapAndApplyHeader(new org.agrona.concurrent.UnsafeBuffer(bytes), 0, new MessageHeaderDecoder());
            seen.add(copy);
            reservations.deliver(d.correlationId(), result);
        });
    }

    private int reserveWhileAnswering(SessionLimits worker, int result) throws Exception {
        CompletableFuture<Integer> outcome = CompletableFuture.supplyAsync(() -> worker.reserve(11, 22, 3));
        while (!outcome.isDone()) {
            answerAll(result);
            Thread.onSpinWait();
        }
        return outcome.get();
    }

    @Test
    void eachWorkerGetsTheAnswerToItsOwnRequest() throws Exception {
        SessionLimits worker = reservations.forWorker(2);
        assertThat(reserveWhileAnswering(worker, SessionLimits.GRANTED)).isEqualTo(SessionLimits.GRANTED);
        assertThat(reserveWhileAnswering(worker, SessionLimits.DENIED)).isEqualTo(SessionLimits.DENIED);
        assertThat(reserveWhileAnswering(worker, SessionLimits.UNSUPPORTED)).isEqualTo(SessionLimits.UNSUPPORTED);
        assertThat(reserveWhileAnswering(worker, 3))
                .as("CAPACITY: not answered")
                .isEqualTo(SessionLimits.UNAVAILABLE);
        AuthReservationDecoder request = seen.get(0);
        assertThat(request.gatewayId()).isEqualTo(7);
        assertThat(request.userKey()).isEqualTo(11);
        assertThat(request.deviceKey()).isEqualTo(22);
        assertThat(request.maxDevices()).isEqualTo(3);
        assertThat(request.ttlSeconds()).isEqualTo(45);
        assertThat(seen.stream().map(AuthReservationDecoder::correlationId).distinct())
                .hasSize(4);
    }

    @Test
    void noAnswerInTimeIsUnavailableAndALateAnswerIsIgnored() throws Exception {
        SessionLimits worker = reservations.forWorker(1);
        long start = System.nanoTime();
        assertThat(worker.reserve(1, 2, 1)).isEqualTo(SessionLimits.UNAVAILABLE);
        assertThat(System.nanoTime() - start)
                .isGreaterThanOrEqualTo(Duration.ofMillis(300).toNanos());
        answerAll(SessionLimits.DENIED); // the late answer to the first request
        assertThat(reserveWhileAnswering(worker, SessionLimits.GRANTED)).isEqualTo(SessionLimits.GRANTED);
        reservations.deliver(5, SessionLimits.DENIED); // not a reservation id
        reservations.deliver((1L << 62) | (99L << 40), SessionLimits.DENIED); // no such worker
    }
}
