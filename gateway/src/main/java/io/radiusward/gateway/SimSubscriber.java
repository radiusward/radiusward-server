/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * A SIM subscriber's keys from the check items of its store entry (ADR 0061), under the names of either other-server
 * line: {@code SIM-Ki}/{@code EAP-Sim-Ki}, {@code SIM-OPc}, {@code SIM-OP}, {@code SIM-AMF}, {@code SIM-SQN},
 * {@code SIM-Algo-Version}/{@code EAP-Sim-Algo-Version}, and stored triplets {@code EAP-Sim-Rand1…3},
 * {@code EAP-Sim-SRES1…3}, {@code EAP-Sim-KC1…3}. Values are hex, with or without {@code 0x}; SQN is a number.
 *
 * @param ki the 16-byte Ki, {@code null} if none
 * @param opc OPc, given or derived from OP; {@code null} if neither
 * @param amf the AMF (2 bytes), {@code null} if not stored
 * @param sqn the stored SQN, the floor for the cluster's sequence; 0 if not stored
 * @param algorithm {@code SIM-Algo-Version}: 4 GSM-MILENAGE, 5 MILENAGE, 0 not stored (MILENAGE when OPc is known)
 * @param triplets stored GSM triplets (RAND, SRES, Kc), empty if none
 */
record SimSubscriber(byte[] ki, byte[] opc, byte[] amf, long sqn, int algorithm, List<Milenage.Triplet> triplets) {

    static final int COMP128_4 = 4;
    static final int MILENAGE = 5;

    /**
     * Reads the keys; throws {@link IllegalArgumentException} with the item's name for a value that does not parse, so
     * the caller can log it once and refuse the subscriber.
     */
    static SimSubscriber of(List<AttributeItem> checks) {
        byte[] ki = null;
        byte[] opc = null;
        byte[] op = null;
        byte[] amf = null;
        long sqn = 0;
        int algorithm = 0;
        byte[][] rand = new byte[3][];
        byte[][] sres = new byte[3][];
        byte[][] kc = new byte[3][];
        for (AttributeItem item : checks) {
            String name = item.attribute().toLowerCase(Locale.ROOT);
            String value = item.value().trim();
            switch (name) {
                case "sim-ki", "eap-sim-ki" -> ki = hex(item, value, 16);
                case "sim-opc" -> opc = hex(item, value, 16);
                case "sim-op" -> op = hex(item, value, 16);
                case "sim-amf" -> amf = hex(item, value, 2);
                case "sim-sqn" -> sqn = number(item, value);
                case "sim-algo-version", "eap-sim-algo-version" -> algorithm = algorithm(item, value);
                default -> {
                    if (name.startsWith("eap-sim-rand") && name.length() == 13) {
                        rand[index(item, name)] = hex(item, value, 16);
                    } else if (name.startsWith("eap-sim-sres") && name.length() == 13) {
                        sres[index(item, name)] = hex(item, value, 4);
                    } else if (name.startsWith("eap-sim-kc") && name.length() == 11) {
                        kc[index(item, name)] = hex(item, value, 8);
                    }
                }
            }
        }
        if (opc == null && op != null && ki != null) {
            opc = Milenage.opc(ki, op);
        }
        if (op != null) {
            java.util.Arrays.fill(op, (byte) 0);
        }
        List<Milenage.Triplet> triplets = new java.util.ArrayList<>();
        for (int i = 0; i < 3; i++) {
            if (rand[i] != null && sres[i] != null && kc[i] != null) {
                triplets.add(new Milenage.Triplet(rand[i], sres[i], kc[i]));
            }
        }
        return new SimSubscriber(ki, opc, amf, sqn, algorithm, List.copyOf(triplets));
    }

    /** Zeroes Ki and OPc once the vectors are computed; the subscriber is unusable afterwards. */
    void erase() {
        if (ki != null) {
            java.util.Arrays.fill(ki, (byte) 0);
        }
        if (opc != null) {
            java.util.Arrays.fill(opc, (byte) 0);
        }
    }

    /** Whether vectors can be computed: a Ki and an OPc, and no COMP128 v1–3 (not supported, ADR 0061). */
    boolean usesMilenage() {
        return ki != null && opc != null && (algorithm == 0 || algorithm == MILENAGE || algorithm == COMP128_4);
    }

    /** {@link #usesMilenage()} or three stored triplets: what EAP-SIM can use. */
    boolean gsm() {
        return usesMilenage() || triplets.size() == 3;
    }

    private static byte[] hex(AttributeItem item, String value, int length) {
        String hex = value.startsWith("0x") || value.startsWith("0X") ? value.substring(2) : value;
        try {
            byte[] b = HexFormat.of().parseHex(hex);
            if (b.length != length) {
                throw new IllegalArgumentException(item.attribute() + ": " + length + " bytes expected");
            }
            return b;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(item.attribute() + ": " + length + " bytes of hex expected", e);
        }
    }

    private static long number(AttributeItem item, String value) {
        try {
            long n = value.startsWith("0x") ? Long.parseLong(value.substring(2), 16) : Long.parseLong(value);
            if (n < 0 || n >= 1L << 48) {
                throw new NumberFormatException(value);
            }
            return n;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(item.attribute() + ": a sequence number of 48 bits expected", e);
        }
    }

    private static int algorithm(AttributeItem item, String value) {
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "comp128-1", "1" -> 1;
            case "comp128-2", "2" -> 2;
            case "comp128-3", "3" -> 3;
            case "comp128-4", "4" -> COMP128_4;
            case "milenage", "5" -> MILENAGE;
            default ->
                throw new IllegalArgumentException(
                        item.attribute() + ": Milenage or Comp128-4 (1-3 are not supported)");
        };
    }

    private static int index(AttributeItem item, String name) {
        int i = name.charAt(name.length() - 1) - '1';
        if (i < 0 || i > 2) {
            throw new IllegalArgumentException(item.attribute() + ": 1, 2 or 3");
        }
        return i;
    }
}
