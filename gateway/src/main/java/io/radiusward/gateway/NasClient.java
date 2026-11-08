/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

/**
 * A configured NAS ({@code nas.<name>.*}).
 *
 * @param name configuration name
 * @param id stable identity used in event keys; the same on every gateway (FNV-1a of the name unless
 *     {@code nas.<name>.id} is set)
 * @param network IPv4 network address as an int
 * @param prefixLength CIDR prefix length, 32 for a single address
 * @param secret shared secret bytes
 * @param vendor vendor profile name (informational in Phase 1)
 * @param messageAuthenticator {@code required}, {@code optional} or {@code off}
 */
public record NasClient(
        String name,
        int id,
        int network,
        int prefixLength,
        byte[] secret,
        String vendor,
        MessageAuthenticatorPolicy messageAuthenticator) {

    /** How Message-Authenticator is treated for requests from this NAS. */
    public enum MessageAuthenticatorPolicy {
        /** Requests without a valid Message-Authenticator are dropped; responses carry one. */
        REQUIRED,
        /** Verified when present; responses carry one when the request had one. */
        OPTIONAL,
        /** Not verified, never sent. */
        OFF
    }

    public int mask() {
        return prefixLength == 0 ? 0 : -1 << (32 - prefixLength);
    }

    public boolean matches(int address) {
        return (address & mask()) == (network & mask());
    }
}
