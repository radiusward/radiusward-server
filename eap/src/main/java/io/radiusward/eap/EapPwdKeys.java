/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * EAP-pwd's cryptography (RFC 5931) for group 19, the same for the server and the peer: the password element, H, the
 * KDF, the Confirm values and the MSK.
 */
public final class EapPwdKeys {

    /** Group 19 (P-256), random function 1, PRF 1 (HMAC-SHA256): the ciphersuite in Confirm and the session ID. */
    public static final byte[] CIPHERSUITE = {0, 19, 1, 1};

    private EapPwdKeys() {}

    /**
     * A Confirm value (§2.8.5.3): H(k | own element | own scalar | other element | other scalar | ciphersuite), from
     * the sender's point of view.
     */
    public static byte[] confirm(
            BigInteger k, P256.Point element, BigInteger scalar, P256.Point otherElement, BigInteger otherScalar) {
        return h(
                P256.bytes(k),
                element.encode(),
                P256.bytes(scalar),
                otherElement.encode(),
                P256.bytes(otherScalar),
                CIPHERSUITE);
    }

    /**
     * The MSK (§2.9): MK = H(k | peer's Confirm | server's Confirm), Session-ID = EAP type 52 | H(ciphersuite | peer's
     * scalar | server's scalar), the first 64 of 128 bytes of KDF(MK, Session-ID).
     */
    public static byte[] msk(
            BigInteger k, byte[] peerConfirm, byte[] serverConfirm, BigInteger peerScalar, BigInteger serverScalar) {
        byte[] sessionId = new byte[33];
        sessionId[0] = (byte) EapPacket.TYPE_PWD;
        System.arraycopy(h(CIPHERSUITE, P256.bytes(peerScalar), P256.bytes(serverScalar)), 0, sessionId, 1, 32);
        byte[] mk = h(P256.bytes(k), peerConfirm, serverConfirm);
        return Arrays.copyOf(kdf(mk, sessionId, 128 * 8), 64);
    }

    /**
     * The password element (§2.8.4.1, hunting and pecking): pwd-seed = H(token | peer-id | server-id | password |
     * counter); pwd-value = KDF(pwd-seed, "EAP-pwd Hunting And Pecking", 256); the first value below p whose y² is a
     * quadratic residue gives x, and y has the parity of pwd-seed's last bit. All 40 rounds always run.
     */
    public static P256.Point passwordElement(byte[] password, byte[] serverId, byte[] peerId, byte[] token) {
        BigInteger x = null;
        boolean odd = false;
        for (int counter = 1; counter <= 40; counter++) {
            byte[] seed = h(token, peerId, serverId, password, new byte[] {(byte) counter});
            BigInteger value = new BigInteger(
                    1, kdf(seed, "EAP-pwd Hunting And Pecking".getBytes(StandardCharsets.US_ASCII), 256));
            boolean residue = value.compareTo(P256.P) < 0 && P256.isQuadraticResidue(P256.ySquared(value.mod(P256.P)));
            if (residue && x == null) {
                x = value;
                odd = (seed[31] & 1) == 1;
            }
        }
        if (x == null) {
            return null;
        }
        BigInteger y = P256.sqrt(P256.ySquared(x));
        if (y.testBit(0) != odd) {
            y = P256.P.subtract(y);
        }
        P256.Point point = new P256.Point(x, y);
        return P256.onCurve(point) ? point : null;
    }

    /** H: HMAC-SHA256 with a zero key over the parts (§2.4). */
    public static byte[] h(byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
            for (byte[] part : parts) {
                mac.update(part);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The KDF (§2.5): K(i) = HMAC-SHA256(key, K(i-1) | i | label | L), i and L 16-bit, L the length in bits; the
     * result truncated to L bits.
     */
    public static byte[] kdf(byte[] key, byte[] label, int bits) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            int bytes = (bits + 7) / 8;
            byte[] out = new byte[bytes];
            byte[] previous = new byte[0];
            for (int i = 1, at = 0; at < bytes; i++) {
                mac.update(previous);
                mac.update(new byte[] {(byte) (i >>> 8), (byte) i});
                mac.update(label);
                mac.update(new byte[] {(byte) (bits >>> 8), (byte) bits});
                previous = mac.doFinal();
                int n = Math.min(previous.length, bytes - at);
                System.arraycopy(previous, 0, out, at, n);
                at += n;
            }
            if (bits % 8 != 0) {
                out[bytes - 1] &= (byte) (0xFF << (8 - bits % 8));
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
