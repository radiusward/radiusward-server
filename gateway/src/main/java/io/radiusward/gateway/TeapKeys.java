/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TEAP's key hierarchy (RFC 7170 §5, as RFC 9930 and wpa_supplicant 2.12 apply it; ADR 0041). TLS-PRF is the TLS 1.2
 * PRF with the negotiated cipher suite's hash (SHA-384 for {@code _SHA384} suites, else SHA-256), also under TLS 1.3;
 * the Compound MAC is an HMAC with the suite's MAC hash (SHA-1 for the CBC {@code _SHA} suites), truncated to 20 bytes.
 *
 * <pre>
 * S-IMCK[0] = session_key_seed (TLS exporter "EXPORTER: teap session key seed", 40)
 * IMSK[j]   = TLS-PRF(EMSK[j], "TEAPbindkey@ietf.org", 0x00 0x00 0x40, 32)   -- or MSK[j] (32, zero padded), or zeros
 * IMCK[j]   = TLS-PRF(S-IMCK[j-1], "Inner Methods Compound Keys", IMSK[j], 60)
 * S-IMCK[j] = IMCK[j][0..40), CMK[j] = IMCK[j][40..60)
 * MSK       = TLS-PRF(S-IMCK[n], "Session Key Generating Function", 64)
 * </pre>
 */
final class TeapKeys {

    static final int SIMCK_LENGTH = 40;
    static final int CMK_LENGTH = 20;
    static final int MAC_LENGTH = 20;

    private final String prfAlgorithm;
    private final String macAlgorithm;

    /** @param cipherSuite the negotiated TLS cipher suite's standard name */
    TeapKeys(String cipherSuite) {
        boolean sha384 = cipherSuite.endsWith("_SHA384");
        this.prfAlgorithm = sha384 ? "HmacSHA384" : "HmacSHA256";
        this.macAlgorithm = sha384 ? "HmacSHA384" : cipherSuite.endsWith("_SHA") ? "HmacSHA1" : "HmacSHA256";
    }

    /** S-IMCK[j] and CMK[j] after an inner method. */
    record Compound(byte[] simck, byte[] cmk) {}

    /**
     * The next S-IMCK and CMK from the previous S-IMCK and the inner method's keys.
     *
     * @param msk the inner method's MSK, {@code null} if it has none (EAP-GTC, EAP-MD5, Basic-Password-Auth)
     * @param emsk the inner method's EMSK, {@code null} if it has none: then the MSK-based IMSK is used
     */
    Compound next(byte[] previousSimck, byte[] msk, byte[] emsk) {
        byte[] imsk = new byte[32];
        if (emsk != null) {
            imsk = Arrays.copyOf(prf(emsk, "TEAPbindkey@ietf.org", new byte[] {0, 0, 64}, 64), 32);
        } else if (msk != null) {
            System.arraycopy(msk, 0, imsk, 0, Math.min(32, msk.length));
        }
        byte[] imck = prf(previousSimck, "Inner Methods Compound Keys", imsk, 60);
        Arrays.fill(imsk, (byte) 0);
        return new Compound(Arrays.copyOf(imck, SIMCK_LENGTH), Arrays.copyOfRange(imck, SIMCK_LENGTH, 60));
    }

    /** The MSK at the end of the conversation. */
    byte[] msk(byte[] simck) {
        return prf(simck, "Session Key Generating Function", new byte[0], 64);
    }

    /**
     * A Compound MAC (§5.3) over the Crypto-Binding TLV with both MAC fields zeroed, the EAP type of TEAP, and the
     * Outer TLVs of the server's and the peer's first messages.
     *
     * @param binding the whole Crypto-Binding TLV (header and value), MAC fields as they are; zeroed in a copy
     */
    byte[] compoundMac(byte[] cmk, byte[] binding, byte[] serverOuterTlvs, byte[] peerOuterTlvs) {
        byte[] zeroed = binding.clone();
        Arrays.fill(zeroed, 4 + 4 + 32, zeroed.length, (byte) 0); // EMSK and MSK Compound MAC
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(new SecretKeySpec(cmk, macAlgorithm));
            mac.update(zeroed);
            mac.update((byte) Teap.TYPE);
            mac.update(serverOuterTlvs);
            mac.update(peerOuterTlvs);
            return Arrays.copyOf(mac.doFinal(), MAC_LENGTH);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The TLS 1.2 PRF (RFC 5246 §5): P_hash(secret, label + seed). */
    byte[] prf(byte[] secret, String label, byte[] seed, int length) {
        try {
            Mac mac = Mac.getInstance(prfAlgorithm);
            mac.init(new SecretKeySpec(secret.length == 0 ? new byte[1] : secret, prfAlgorithm));
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            byte[] labelSeed = new byte[labelBytes.length + seed.length];
            System.arraycopy(labelBytes, 0, labelSeed, 0, labelBytes.length);
            System.arraycopy(seed, 0, labelSeed, labelBytes.length, seed.length);
            byte[] out = new byte[length];
            byte[] a = labelSeed;
            for (int at = 0; at < length; ) {
                mac.update(a);
                a = mac.doFinal();
                mac.update(a);
                mac.update(labelSeed);
                byte[] block = mac.doFinal();
                int n = Math.min(block.length, length - at);
                System.arraycopy(block, 0, out, at, n);
                at += n;
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
