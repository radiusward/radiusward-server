/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.eap.Milenage;

/**
 * A simulated SIM or USIM for EAP-SIM, EAP-AKA and EAP-AKA′ ({@link EapLogin#sim}, {@link EapLogin#aka},
 * {@link EapLogin#akaPrime}): the subscriber's IMSI, its key Ki and the operator's OPc, with MILENAGE as the
 * authentication algorithm. Like a USIM it remembers the highest sequence number it accepted, so a network that
 * repeats an old one gets a synchronization failure; keep the card between logins to see that.
 */
public final class SimCard {

    private final String imsi;
    private final byte[] ki;
    private final byte[] opc;
    private long sqn;

    /** A card with the operator variant already derived (OPc). */
    public SimCard(String imsi, byte[] ki, byte[] opc) {
        if (!imsi.matches("[0-9]{6,15}")) {
            throw new IllegalArgumentException("an IMSI is 6 to 15 digits: " + imsi);
        }
        if (ki.length != 16 || opc.length != 16) {
            throw new IllegalArgumentException("Ki and OPc are 16 bytes each");
        }
        this.imsi = imsi;
        this.ki = ki.clone();
        this.opc = opc.clone();
    }

    /** A card configured with the operator's OP instead of OPc (OPc is derived from Ki and OP). */
    public static SimCard withOp(String imsi, byte[] ki, byte[] op) {
        return new SimCard(imsi, ki, Milenage.opc(ki, op));
    }

    public String imsi() {
        return imsi;
    }

    /** The highest sequence number (SQN) the card accepted; 0 for a new card. */
    public long sqn() {
        return sqn;
    }

    /** Sets the card's SQN, e.g. ahead of the network's to test resynchronization. */
    public SimCard sqn(long sqn) {
        if (sqn < 0 || sqn >= 1L << 48) {
            throw new IllegalArgumentException("SQN is 48 bits");
        }
        this.sqn = sqn;
        return this;
    }

    Milenage milenage() {
        return new Milenage(ki, opc);
    }

    void accepted(long sqn) {
        this.sqn = sqn;
    }
}
