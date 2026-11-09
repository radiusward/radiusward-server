/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * EAP-MD5 (RFC 3748 §5.4): a CHAP-like challenge, answered with MD5(identifier ‖ password ‖ challenge). Needs the
 * cleartext password, so only for stores that allow it like CHAP ({@code auth.store.<name>.chap}); derives no keys.
 * Here mainly to carry the EAP framework's plumbing; real deployments use the TLS-based methods (5.8).
 */
final class EapMd5 implements EapMethod {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final byte[] challenge = new byte[16];

    @Override
    public int type() {
        return EapPacket.TYPE_MD5;
    }

    @Override
    public Step start(int identifier, Credentials credentials) {
        RANDOM.nextBytes(challenge);
        byte[] data = new byte[1 + challenge.length];
        data[0] = (byte) challenge.length;
        System.arraycopy(challenge, 0, data, 1, challenge.length);
        return Step.next(data);
    }

    @Override
    public Step process(int identifier, byte[] data, Credentials credentials) {
        if (data.length < 17 || (data[0] & 0xFF) != 16 || !credentials.cleartextAllowed()) {
            return Step.FAILED;
        }
        for (AttributeItem p : credentials.passwords()) {
            if (p.attribute().equalsIgnoreCase(PasswordCheck.CLEARTEXT)) {
                try {
                    MessageDigest md5 = MessageDigest.getInstance("MD5");
                    md5.update((byte) identifier);
                    md5.update(p.value().getBytes(StandardCharsets.UTF_8));
                    md5.update(challenge);
                    byte[] value = java.util.Arrays.copyOfRange(data, 1, 17);
                    return MessageDigest.isEqual(md5.digest(), value) ? Step.succeeded(null) : Step.FAILED;
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        return Step.FAILED;
    }
}
