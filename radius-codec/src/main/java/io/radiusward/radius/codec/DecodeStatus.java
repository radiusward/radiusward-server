/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

/**
 * Outcome of decoding a datagram. Returned instead of throwing so the receive path never allocates
 * on bad input; anything but {@link #OK} means the packet must be silently discarded (RFC 2865 §3).
 */
public enum DecodeStatus {
    OK,
    /** Fewer than 20 bytes received. */
    TOO_SHORT,
    /** Length field below 20 or above 4096. */
    INVALID_LENGTH,
    /** Length field larger than the received datagram. */
    TRUNCATED,
    /** An attribute has a length below 2 or runs past the end of the packet. */
    MALFORMED_ATTRIBUTE,
    /** Message-Authenticator present with a length other than 18. */
    MALFORMED_MESSAGE_AUTHENTICATOR
}
