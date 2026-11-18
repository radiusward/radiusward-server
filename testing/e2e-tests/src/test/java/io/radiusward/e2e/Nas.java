/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import io.radiusward.testing.AccountingRequest;
import io.radiusward.testing.FakeNas;
import java.time.Duration;

/**
 * A simulated NAS with a fixed source port, retransmitting like a real one: {@link FakeNas} with the requests these
 * tests send, whose Event-Timestamp advances with the session time.
 */
final class Nas implements AutoCloseable {

    static final byte[] SECRET = FakeNas.SECRET;

    private final FakeNas nas = new FakeNas();

    /** Sends and waits for a verified Accounting-Response; {@code null} if none arrives within the attempts. */
    byte[] exchange(int port, byte[] request, int attempts, Duration timeout) {
        return nas.exchange(port, request, attempts, timeout);
    }

    /** Sends any request and waits for its verified answer, whatever its code; {@code null} if none arrives. */
    byte[] answer(int port, byte[] request, int attempts, Duration timeout) {
        return nas.answer(port, request, attempts, timeout);
    }

    /** Like {@link #exchange} with NAS-like defaults (3 s, 10 attempts), failing if there is no answer. */
    byte[] ack(int port, byte[] request) {
        byte[] response = exchange(port, request, 10, Duration.ofSeconds(3));
        if (response == null) {
            throw new AssertionError("no Accounting-Response to request " + (request[1] & 0xFF));
        }
        return response;
    }

    static byte[] request(int id, int status, String sessionId, long sessionTime) {
        return request(id, status, sessionId, sessionTime, 0);
    }

    static byte[] request(int id, int status, String sessionId, long sessionTime, int delay) {
        return request(id, status, sessionId, sessionTime, delay, null);
    }

    /** A request from a device behind NAT, identified by {@code nasIdentifier} ({@code null}: none). */
    static byte[] request(int id, int status, String sessionId, long sessionTime, int delay, String nasIdentifier) {
        return AccountingRequest.of(id, status)
                .nasIdentifier(nasIdentifier)
                .session(sessionId)
                .sessionTime(sessionTime)
                .eventTimestamp(AccountingRequest.EVENT_TIMESTAMP + sessionTime)
                .delay(delay)
                .build();
    }

    static long[] sessionKey(String sessionId) {
        return AccountingRequest.sessionKey(sessionId);
    }

    /** The session key of a device's session when the NAS entry identifies devices by NAS-Identifier. */
    static long[] sessionKey(String sessionId, String nasIdentifier) {
        return AccountingRequest.sessionKey(sessionId, nasIdentifier);
    }

    @Override
    public void close() throws java.io.IOException {
        nas.close();
    }
}
