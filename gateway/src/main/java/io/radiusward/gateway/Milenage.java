/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * The MILENAGE algorithm set (3GPP TS 35.206) with which an authentication centre and a USIM compute the same vectors
 * from the subscriber key K and the operator variant OPc (ADR 0061), and GSM-MILENAGE (TS 55.205), its GSM triplets.
 * Written from the specification; checked against the test sets of TS 35.207/35.208.
 */
final class Milenage {

    /** f1 rotation and constants (TS 35.206 §4.1): r1..r5 in bytes, c1..c5 in their last byte. */
    private static final int[] ROTATE = {8, 0, 4, 8, 12};

    private static final int[] CONSTANT = {0, 1, 2, 4, 8};

    private final Cipher aes;
    private final byte[] opc;

    /**
     * @param k the 16-byte subscriber key
     * @param opc the 16-byte OPc ({@link #opc} derives it from OP)
     */
    Milenage(byte[] k, byte[] opc) {
        if (k.length != 16 || opc.length != 16) {
            throw new IllegalArgumentException("K and OPc are 16 bytes");
        }
        this.aes = aes(k);
        this.opc = opc.clone();
    }

    /** OPc = E_K(OP) ⊕ OP. */
    static byte[] opc(byte[] k, byte[] op) {
        byte[] out = encrypt(aes(k), op);
        xor(out, op);
        return out;
    }

    /** A UMTS vector for a challenge: RES, CK, IK and AK (f2–f5), plus f5* for resynchronisation. */
    record Quintet(byte[] res, byte[] ck, byte[] ik, byte[] ak, byte[] akStar) {}

    /** f2, f3, f4, f5 and f5* for {@code rand}. */
    Quintet f2345(byte[] rand) {
        byte[] temp = temp(rand);
        byte[] out2 = out(temp, 1);
        byte[] out3 = out(temp, 2);
        byte[] out4 = out(temp, 3);
        byte[] out5 = out(temp, 4);
        return new Quintet(
                java.util.Arrays.copyOfRange(out2, 8, 16),
                out3,
                out4,
                java.util.Arrays.copyOfRange(out2, 0, 6),
                java.util.Arrays.copyOfRange(out5, 0, 6));
    }

    /**
     * f1 and f1*: the network authentication code MAC-A (bytes 0–7) and the resynchronisation code MAC-S (8–15) over
     * SQN and AMF.
     */
    byte[] f1(byte[] rand, byte[] sqn, byte[] amf) {
        if (sqn.length != 6 || amf.length != 2) {
            throw new IllegalArgumentException("SQN is 6 bytes, AMF 2");
        }
        byte[] temp = temp(rand);
        byte[] in1 = new byte[16];
        System.arraycopy(sqn, 0, in1, 0, 6);
        System.arraycopy(amf, 0, in1, 6, 2);
        System.arraycopy(in1, 0, in1, 8, 8);
        xor(in1, opc);
        byte[] x = rotate(in1, ROTATE[0]);
        xor(x, temp);
        x[15] ^= (byte) CONSTANT[0];
        byte[] out1 = encrypt(aes, x);
        xor(out1, opc);
        return out1;
    }

    /** AUTN = SQN ⊕ AK ‖ AMF ‖ MAC-A (TS 33.102 §6.3.2). */
    byte[] autn(byte[] rand, byte[] sqn, byte[] amf) {
        byte[] ak = f2345(rand).ak();
        byte[] mac = f1(rand, sqn, amf);
        byte[] autn = new byte[16];
        for (int i = 0; i < 6; i++) {
            autn[i] = (byte) (sqn[i] ^ ak[i]);
        }
        System.arraycopy(amf, 0, autn, 6, 2);
        System.arraycopy(mac, 0, autn, 8, 8);
        return autn;
    }

    /**
     * The SQN of a USIM that rejected a challenge as out of step, from its AUTS = SQN_MS ⊕ AK* ‖ MAC-S, or
     * {@code null} if MAC-S does not verify (TS 33.102 §6.3.5; the AMF of the check is zero).
     */
    byte[] resync(byte[] rand, byte[] auts) {
        if (auts.length != 14) {
            return null;
        }
        byte[] akStar = f2345(rand).akStar();
        byte[] sqnMs = new byte[6];
        for (int i = 0; i < 6; i++) {
            sqnMs[i] = (byte) (auts[i] ^ akStar[i]);
        }
        byte[] macS = java.util.Arrays.copyOfRange(f1(rand, sqnMs, new byte[2]), 8, 16);
        return java.security.MessageDigest.isEqual(macS, java.util.Arrays.copyOfRange(auts, 6, 14)) ? sqnMs : null;
    }

    /** A GSM triplet's SRES (4 bytes) and Kc (8 bytes). */
    record Triplet(byte[] rand, byte[] sres, byte[] kc) {}

    /** GSM-MILENAGE (TS 55.205, conversion functions c2 and c3 of TS 33.102): SRES and Kc for {@code rand}. */
    Triplet gsm(byte[] rand) {
        Quintet q = f2345(rand);
        byte[] sres = new byte[4];
        for (int i = 0; i < 4; i++) {
            sres[i] = (byte) (q.res()[i] ^ q.res()[i + 4]);
        }
        byte[] kc = new byte[8];
        for (int i = 0; i < 8; i++) {
            kc[i] = (byte) (q.ck()[i] ^ q.ck()[i + 8] ^ q.ik()[i] ^ q.ik()[i + 8]);
        }
        return new Triplet(rand.clone(), sres, kc);
    }

    private byte[] temp(byte[] rand) {
        if (rand.length != 16) {
            throw new IllegalArgumentException("RAND is 16 bytes");
        }
        byte[] x = rand.clone();
        xor(x, opc);
        return encrypt(aes, x);
    }

    /** OUT_n = E_K(rot(TEMP ⊕ OPc, r_n) ⊕ c_n) ⊕ OPc for n = 2..5 ({@code index} 1..4). */
    private byte[] out(byte[] temp, int index) {
        byte[] x = temp.clone();
        xor(x, opc);
        x = rotate(x, ROTATE[index]);
        x[15] ^= (byte) CONSTANT[index];
        byte[] out = encrypt(aes, x);
        xor(out, opc);
        return out;
    }

    private static byte[] rotate(byte[] x, int bytes) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            out[i] = x[(i + bytes) % 16];
        }
        return out;
    }

    private static void xor(byte[] into, byte[] with) {
        for (int i = 0; i < into.length; i++) {
            into[i] ^= with[i];
        }
    }

    private static Cipher aes(byte[] k) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding"); // one block at a time, the MILENAGE kernel
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"));
            return c;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] encrypt(Cipher aes, byte[] block) {
        try {
            return aes.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
