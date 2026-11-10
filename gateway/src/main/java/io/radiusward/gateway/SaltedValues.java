/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;

/**
 * Re-encrypts salted attribute values for another secret and request authenticator (RFC 2548 §2.4.2 MS-MPPE keys,
 * RFC 2868 §3.5 Tunnel-Password): what a proxy does to a home server's reply before it goes to the NAS (ADR 0037).
 * The salt stays; the blocks are decrypted with one secret and encrypted with the other. One instance per thread,
 * allocation-free.
 */
final class SaltedValues {

    private final MessageDigest md5;
    private final byte[] digest = new byte[16];
    private final byte[] plain = new byte[256];
    private final byte[] previous = new byte[16];

    SaltedValues() {
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 is part of every JDK", e);
        }
    }

    /**
     * Re-encrypts {@code length} bytes at {@code offset} — two bytes of salt, then blocks of 16 — in place.
     *
     * @return {@code false} if the value is not salt plus whole blocks
     */
    boolean reencrypt(
            MutableDirectBuffer value,
            int offset,
            int length,
            byte[] fromSecret,
            DirectBuffer fromAuthenticator,
            int fromAuthenticatorOffset,
            byte[] toSecret,
            DirectBuffer toAuthenticator,
            int toAuthenticatorOffset) {
        int blocks = length - 2;
        if (blocks <= 0 || blocks % 16 != 0 || blocks > plain.length) {
            return false;
        }
        try {
            // decrypt: b(1) = MD5(secret + authenticator + salt), b(i) = MD5(secret + c(i-1))
            for (int at = 0; at < blocks; at += 16) {
                md5.update(fromSecret);
                if (at == 0) {
                    for (int i = 0; i < 16; i++) {
                        md5.update(fromAuthenticator.getByte(fromAuthenticatorOffset + i));
                    }
                    md5.update(value.getByte(offset));
                    md5.update(value.getByte(offset + 1));
                } else {
                    md5.update(previous, 0, 16);
                }
                md5.digest(digest, 0, 16);
                for (int i = 0; i < 16; i++) {
                    byte c = value.getByte(offset + 2 + at + i);
                    previous[i] = c;
                    plain[at + i] = (byte) (c ^ digest[i]);
                }
            }
            // encrypt again with the same salt
            for (int at = 0; at < blocks; at += 16) {
                md5.update(toSecret);
                if (at == 0) {
                    for (int i = 0; i < 16; i++) {
                        md5.update(toAuthenticator.getByte(toAuthenticatorOffset + i));
                    }
                    md5.update(value.getByte(offset));
                    md5.update(value.getByte(offset + 1));
                } else {
                    md5.update(previous, 0, 16);
                }
                md5.digest(digest, 0, 16);
                for (int i = 0; i < 16; i++) {
                    byte c = (byte) (plain[at + i] ^ digest[i]);
                    previous[i] = c;
                    value.putByte(offset + 2 + at + i, c);
                }
            }
            return true;
        } catch (DigestException e) {
            throw new IllegalStateException(e);
        }
    }
}
