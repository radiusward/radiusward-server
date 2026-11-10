/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Key derivation of EAP-SIM (RFC 4186 §7), EAP-AKA (RFC 4187 §7) and EAP-AKA′ (RFC 9048 §3.3–3.4), ADR 0061: the
 * master key, the FIPS 186-2 pseudo-random function (change notice 1, as RFC 4186 Appendix B specifies) or PRF′ with
 * HMAC-SHA-256, and the keys cut from their output.
 */
final class SimKeys {

    private SimKeys() {}

    /**
     * K_encr (AT_ENCR_DATA), K_aut (AT_MAC), K_re (AKA′ fast re-authentication; {@code null} otherwise), MSK, EMSK.
     */
    record Keys(byte[] kEncr, byte[] kAut, byte[] kRe, byte[] msk, byte[] emsk) {}

    /** EAP-SIM: MK = SHA1(Identity ‖ n×Kc ‖ NONCE_MT ‖ Version List ‖ Selected Version). */
    static byte[] simMasterKey(byte[] identity, byte[][] kc, byte[] nonceMt, byte[] versionList, int selected) {
        MessageDigest sha1 = sha1();
        sha1.update(identity);
        for (byte[] k : kc) {
            sha1.update(k);
        }
        sha1.update(nonceMt);
        sha1.update(versionList);
        sha1.update(new byte[] {(byte) (selected >>> 8), (byte) selected});
        return sha1.digest();
    }

    /** EAP-AKA: MK = SHA1(Identity ‖ IK ‖ CK). */
    static byte[] akaMasterKey(byte[] identity, byte[] ik, byte[] ck) {
        MessageDigest sha1 = sha1();
        sha1.update(identity);
        sha1.update(ik);
        sha1.update(ck);
        return sha1.digest();
    }

    /** EAP-SIM and EAP-AKA full authentication: K_encr, K_aut, MSK, EMSK from 160 bytes of the PRF. */
    static Keys fullKeys(byte[] mk) {
        byte[] x = fips186Prf(mk, 160);
        return new Keys(
                Arrays.copyOfRange(x, 0, 16),
                Arrays.copyOfRange(x, 16, 32),
                null,
                Arrays.copyOfRange(x, 32, 96),
                Arrays.copyOfRange(x, 96, 160));
    }

    /**
     * EAP-SIM and EAP-AKA fast re-authentication (RFC 4186 §7): XKEY′ = SHA1(Identity ‖ counter ‖ NONCE_S ‖ MK), then
     * MSK and EMSK from the PRF.
     */
    static Keys reauthKeys(byte[] identity, int counter, byte[] nonceS, byte[] mk) {
        MessageDigest sha1 = sha1();
        sha1.update(identity);
        sha1.update(new byte[] {(byte) (counter >>> 8), (byte) counter});
        sha1.update(nonceS);
        sha1.update(mk);
        byte[] x = fips186Prf(sha1.digest(), 128);
        return new Keys(null, null, null, Arrays.copyOfRange(x, 0, 64), Arrays.copyOfRange(x, 64, 128));
    }

    /** XKEY′ as used for AT_MAC of a re-authentication: the same SHA-1 as {@link #reauthKeys}. */
    static byte[] reauthXkey(byte[] identity, int counter, byte[] nonceS, byte[] mk) {
        MessageDigest sha1 = sha1();
        sha1.update(identity);
        sha1.update(new byte[] {(byte) (counter >>> 8), (byte) counter});
        sha1.update(nonceS);
        sha1.update(mk);
        return sha1.digest();
    }

    /**
     * EAP-AKA′: CK′ ‖ IK′ = HMAC-SHA-256(CK ‖ IK, S) with S = FC 0x20 ‖ network name ‖ its length ‖ SQN ⊕ AK ‖ 0x0006
     * (3GPP TS 33.402 Annex A.2); returns CK′ (16 bytes) and IK′ (16 bytes).
     */
    static byte[][] akaPrimeCkIk(byte[] ck, byte[] ik, byte[] networkName, byte[] sqnXorAk) {
        byte[] key = new byte[32];
        System.arraycopy(ck, 0, key, 0, 16);
        System.arraycopy(ik, 0, key, 16, 16);
        Mac mac = hmac256(key);
        mac.update((byte) 0x20);
        mac.update(networkName);
        mac.update(new byte[] {(byte) (networkName.length >>> 8), (byte) networkName.length});
        mac.update(sqnXorAk);
        mac.update(new byte[] {0, 6});
        byte[] out = mac.doFinal();
        return new byte[][] {Arrays.copyOfRange(out, 0, 16), Arrays.copyOfRange(out, 16, 32)};
    }

    /**
     * EAP-AKA′ full authentication (RFC 9048 §3.3): MK = PRF′(IK′ ‖ CK′, "EAP-AKA'" ‖ Identity), cut into K_encr (16),
     * K_aut (32), K_re (32), MSK (64), EMSK (64).
     */
    static Keys akaPrimeKeys(byte[] ckPrime, byte[] ikPrime, byte[] identity) {
        byte[] key = new byte[32];
        System.arraycopy(ikPrime, 0, key, 0, 16);
        System.arraycopy(ckPrime, 0, key, 16, 16);
        byte[] label = "EAP-AKA'".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = new byte[label.length + identity.length];
        System.arraycopy(label, 0, seed, 0, label.length);
        System.arraycopy(identity, 0, seed, label.length, identity.length);
        byte[] mk = prfPrime(key, seed, 208);
        return new Keys(
                Arrays.copyOfRange(mk, 0, 16),
                Arrays.copyOfRange(mk, 16, 48),
                Arrays.copyOfRange(mk, 48, 80),
                Arrays.copyOfRange(mk, 80, 144),
                Arrays.copyOfRange(mk, 144, 208));
    }

    /**
     * EAP-AKA′ fast re-authentication (RFC 9048 §3.3): PRF′(K_re, "EAP-AKA' re-auth" ‖ Identity ‖ counter ‖ NONCE_S)
     * → MSK, EMSK.
     */
    static Keys akaPrimeReauthKeys(byte[] kRe, byte[] identity, int counter, byte[] nonceS) {
        byte[] label = "EAP-AKA' re-auth".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = new byte[label.length + identity.length + 2 + nonceS.length];
        int at = 0;
        System.arraycopy(label, 0, seed, at, label.length);
        at += label.length;
        System.arraycopy(identity, 0, seed, at, identity.length);
        at += identity.length;
        seed[at++] = (byte) (counter >>> 8);
        seed[at++] = (byte) counter;
        System.arraycopy(nonceS, 0, seed, at, nonceS.length);
        byte[] mk = prfPrime(kRe, seed, 128);
        return new Keys(null, null, null, Arrays.copyOfRange(mk, 0, 64), Arrays.copyOfRange(mk, 64, 128));
    }

    /** PRF′ (RFC 9048 §3.4.1): T1 = HMAC-SHA-256(K, S ‖ 1), Tn = HMAC-SHA-256(K, Tn-1 ‖ S ‖ n). */
    static byte[] prfPrime(byte[] key, byte[] seed, int length) {
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        for (int n = 1, at = 0; at < length; n++) {
            Mac mac = hmac256(key);
            mac.update(t);
            mac.update(seed);
            mac.update((byte) n);
            t = mac.doFinal();
            System.arraycopy(t, 0, out, at, Math.min(t.length, length - at));
            at += t.length;
        }
        return out;
    }

    /**
     * The FIPS 186-2 pseudo-random function with change notice 1 as RFC 4186 Appendix B uses it: XSEED is zero, each
     * output block w is the SHA-1 compression of XKEY (no padding), and XKEY = (1 + XKEY + w) mod 2^160.
     */
    static byte[] fips186Prf(byte[] seed, int length) {
        if (seed.length != 20) {
            throw new IllegalArgumentException("the PRF seed is 20 bytes");
        }
        byte[] xkey = seed.clone();
        byte[] out = new byte[length];
        for (int at = 0; at < length; at += 20) {
            byte[] w = sha1Compress(xkey);
            System.arraycopy(w, 0, out, at, Math.min(20, length - at));
            int carry = 1;
            for (int i = 19; i >= 0; i--) {
                int sum = (xkey[i] & 0xFF) + (w[i] & 0xFF) + carry;
                xkey[i] = (byte) sum;
                carry = sum >>> 8;
            }
        }
        return out;
    }

    /** The SHA-1 compression function over one block: the 20 bytes of {@code xval} followed by zeros. */
    static byte[] sha1Compress(byte[] xval) {
        int[] w = new int[80];
        for (int i = 0; i < 5; i++) {
            w[i] = (xval[4 * i] & 0xFF) << 24
                    | (xval[4 * i + 1] & 0xFF) << 16
                    | (xval[4 * i + 2] & 0xFF) << 8
                    | (xval[4 * i + 3] & 0xFF);
        }
        for (int i = 16; i < 80; i++) {
            w[i] = Integer.rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        int h0 = 0x67452301;
        int h1 = 0xEFCDAB89;
        int h2 = 0x98BADCFE;
        int h3 = 0x10325476;
        int h4 = 0xC3D2E1F0;
        int a = h0;
        int b = h1;
        int c = h2;
        int d = h3;
        int e = h4;
        for (int i = 0; i < 80; i++) {
            int f;
            int k;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            int temp = Integer.rotateLeft(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = Integer.rotateLeft(b, 30);
            b = a;
            a = temp;
        }
        int[] h = {h0 + a, h1 + b, h2 + c, h3 + d, h4 + e};
        byte[] out = new byte[20];
        for (int i = 0; i < 5; i++) {
            out[4 * i] = (byte) (h[i] >>> 24);
            out[4 * i + 1] = (byte) (h[i] >>> 16);
            out[4 * i + 2] = (byte) (h[i] >>> 8);
            out[4 * i + 3] = (byte) h[i];
        }
        return out;
    }

    /** AT_MAC of EAP-SIM and EAP-AKA: HMAC-SHA1-128 over the message (MAC zeroed) and {@code extra}. */
    static byte[] macSha1(byte[] kAut, byte[] message, byte[] extra) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(kAut, "HmacSHA1"));
            mac.update(message);
            if (extra != null) {
                mac.update(extra);
            }
            return Arrays.copyOf(mac.doFinal(), 16);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** AT_MAC of EAP-AKA′: HMAC-SHA-256-128 over the message (MAC zeroed) and {@code extra}. */
    static byte[] macSha256(byte[] kAut, byte[] message, byte[] extra) {
        Mac mac = hmac256(kAut);
        mac.update(message);
        if (extra != null) {
            mac.update(extra);
        }
        return Arrays.copyOf(mac.doFinal(), 16);
    }

    private static Mac hmac256(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static MessageDigest sha1() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
