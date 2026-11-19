/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.radius.codec.RadiusCode;
import java.time.Duration;

/**
 * A verified answer to a request of {@link RadiusClient}: its code and attributes, and how it came (the attempt that
 * was answered, the time since the first one).
 */
public final class Response extends ReceivedPacket {

    private final int attempts;
    private final Duration elapsed;

    Response(byte[] bytes, int attempts, Duration elapsed) {
        super(bytes);
        this.attempts = attempts;
        this.elapsed = elapsed;
    }

    public boolean isAccept() {
        return code() == RadiusCode.ACCESS_ACCEPT;
    }

    public boolean isReject() {
        return code() == RadiusCode.ACCESS_REJECT;
    }

    public boolean isChallenge() {
        return code() == RadiusCode.ACCESS_CHALLENGE;
    }

    /** An Accounting-Response, CoA-ACK or Disconnect-ACK. */
    public boolean isAcknowledgement() {
        int c = code();
        return c == RadiusCode.ACCOUNTING_RESPONSE || c == RadiusCode.COA_ACK || c == RadiusCode.DISCONNECT_ACK;
    }

    /** Which attempt was answered: 1 for the first transmission. */
    public int attempts() {
        return attempts;
    }

    /** From the first transmission to the answer. */
    public Duration elapsed() {
        return elapsed;
    }
}
