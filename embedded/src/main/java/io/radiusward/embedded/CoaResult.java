/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

/**
 * What a NAS answered to a CoA or Disconnect-Request for one session.
 *
 * @param errorCause the NAK's Error-Cause (RFC 5176 §3.6), 0 if none
 */
public record CoaResult(String nas, String acctSessionId, String user, Outcome outcome, int errorCause) {

    public enum Outcome {
        /** CoA-ACK or Disconnect-ACK. */
        ACK,
        /** CoA-NAK or Disconnect-NAK. */
        NAK,
        /** No answer after the retries. */
        TIMEOUT,
        /** No address to send to, or too many requests to that NAS in flight. */
        UNREACHABLE
    }

    public boolean acknowledged() {
        return outcome == Outcome.ACK;
    }
}
