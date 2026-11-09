/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** The secure-channel key and credentials of MS-NRPC with AES (§3.1.4.3.1, §3.1.4.4.1). */
final class NetlogonCrypto {

    private NetlogonCrypto() {}

    /** The NT hash of the machine account's password: MD4 of its UTF-16LE form. */
    static byte[] ntHash(String password) {
        return Md4.digest(password.getBytes(StandardCharsets.UTF_16LE));
    }

    /** SessionKey = HMAC-SHA256(NT hash, client challenge ‖ server challenge), first 16 bytes. */
    static byte[] sessionKey(byte[] ntHash, byte[] clientChallenge, byte[] serverChallenge) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(ntHash, "HmacSHA256"));
            mac.update(clientChallenge);
            mac.update(serverChallenge);
            return Arrays.copyOf(mac.doFinal(), 16);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** ComputeNetlogonCredential: AES-128 in CFB8 mode with a zero IV over the 8-byte input. */
    static byte[] credential(byte[] input, byte[] sessionKey) {
        return aesCfb8(sessionKey, new byte[16], input, true);
    }

    static byte[] aesCfb8(byte[] key, byte[] iv, byte[] data, boolean encrypt) {
        try {
            Cipher c = Cipher.getInstance("AES/CFB8/NoPadding");
            c.init(
                    encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
