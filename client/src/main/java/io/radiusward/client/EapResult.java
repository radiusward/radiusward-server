/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import java.util.Optional;

/**
 * How an EAP login ended: accepted (with the Access-Accept's attributes and the keys a NAS would get), rejected, or no
 * answer; how many round trips it took, and what the device checked of the server.
 */
public final class EapResult {

    /** The end of the conversation. */
    public enum Outcome {
        ACCEPTED,
        REJECTED,
        /** The server stopped answering (no Access-Accept, Access-Reject or Access-Challenge). */
        NO_ANSWER
    }

    private final Outcome outcome;
    private final Response response;
    private final int rounds;
    private final byte[] msk;
    private final byte[] serverMsk;
    private final boolean serverProved;
    private final boolean cryptoBound;

    EapResult(
            Outcome outcome,
            Response response,
            int rounds,
            byte[] msk,
            byte[] serverMsk,
            boolean serverProved,
            boolean cryptoBound) {
        this.outcome = outcome;
        this.response = response;
        this.rounds = rounds;
        this.msk = msk;
        this.serverMsk = serverMsk;
        this.serverProved = serverProved;
        this.cryptoBound = cryptoBound;
    }

    public Outcome outcome() {
        return outcome;
    }

    public boolean accepted() {
        return outcome == Outcome.ACCEPTED;
    }

    public boolean rejected() {
        return outcome == Outcome.REJECTED;
    }

    /** The Access-Accept or Access-Reject: its reply attributes (Class, VLAN, Session-Timeout ...). */
    public Optional<Response> response() {
        return Optional.ofNullable(response);
    }

    /** Access-Request round trips, the last one included. */
    public int rounds() {
        return rounds;
    }

    /** The MSK the device derived (TLS-based methods; with PEAP crypto-binding the compound one), else empty. */
    public Optional<byte[]> msk() {
        return Optional.ofNullable(msk).map(byte[]::clone);
    }

    /**
     * The MSK the server sent the NAS in MS-MPPE-Recv-Key and MS-MPPE-Send-Key, decrypted with the secret: equal to
     * {@link #msk()} when both sides hold the same keys (what a Wi-Fi access point relies on).
     */
    public Optional<byte[]> serverMsk() {
        return Optional.ofNullable(serverMsk).map(byte[]::clone);
    }

    /** MS-CHAPv2 inside PEAP or TTLS: the server's authenticator response proved it knew the password. */
    public boolean serverProved() {
        return serverProved;
    }

    /** PEAP: the server's Crypto-Binding verified and was answered, binding the inner method to the tunnel. */
    public boolean cryptoBound() {
        return cryptoBound;
    }

    @Override
    public String toString() {
        return "EapResult[" + outcome + ", rounds=" + rounds + "]";
    }
}
