/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

/** GSM-MILENAGE for tools and tests outside this package: SRES and Kc of a challenge (ADR 0061). */
public final class SimVectors {

    private SimVectors() {}

    /** SRES (4 bytes) and Kc (8 bytes) for {@code rand} from Ki and OPc. */
    public static byte[][] gsm(byte[] ki, byte[] opc, byte[] rand) {
        Milenage milenage = new Milenage(ki, opc);
        Milenage.Triplet t = milenage.gsm(rand);
        milenage.erase();
        return new byte[][] {t.sres(), t.kc()};
    }
}
