/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.List;

/** What the supplicant's conversations share: the random source of nonces and challenges, and joining bytes. */
final class EapBytes {

    static final SecureRandom RANDOM = new SecureRandom();

    private EapBytes() {}

    static byte[] concat(List<byte[]> parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        parts.forEach(out::writeBytes);
        return out.toByteArray();
    }

    static byte[] concat(byte[]... parts) {
        return concat(List.of(parts));
    }
}
