/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * The 24-byte response of MS-CHAP and NTLMv1 to an 8-byte challenge (RFC 2759 ChallengeResponse): three DES
 * encryptions with keys from the zero-padded NT hash. Used to turn a PAP password into a network logon.
 */
final class NtResponse {

    private NtResponse() {}

    static byte[] of(byte[] challenge, byte[] ntHash) {
        byte[] z = Arrays.copyOf(ntHash, 21);
        byte[] out = new byte[24];
        for (int i = 0; i < 3; i++) {
            System.arraycopy(des(Arrays.copyOfRange(z, i * 7, i * 7 + 7), challenge), 0, out, i * 8, 8);
        }
        return out;
    }

    private static byte[] des(byte[] k, byte[] block) {
        byte[] key = {
            (byte) (k[0] & 0xFE),
            (byte) ((k[0] << 7 | (k[1] & 0xFF) >>> 1) & 0xFE),
            (byte) ((k[1] << 6 | (k[2] & 0xFF) >>> 2) & 0xFE),
            (byte) ((k[2] << 5 | (k[3] & 0xFF) >>> 3) & 0xFE),
            (byte) ((k[3] << 4 | (k[4] & 0xFF) >>> 4) & 0xFE),
            (byte) ((k[4] << 3 | (k[5] & 0xFF) >>> 5) & 0xFE),
            (byte) ((k[5] << 2 | (k[6] & 0xFF) >>> 6) & 0xFE),
            (byte) (k[6] << 1 & 0xFE)
        };
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
            return cipher.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("DES is part of every JDK", e);
        }
    }
}
