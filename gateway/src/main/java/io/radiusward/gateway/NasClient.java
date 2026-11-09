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
 * @param identity attributes telling apart the devices behind this entry (NAT), first present wins; empty: the
 *     source address is the device ({@code source-ip}, the default)
 * @param idleTimeoutMinutes a session of this entry without an event for this long is closed (lost Stop); about three
 *     interim intervals. 0: the cluster's {@code service.idle.timeout}
 * @param accessMessageAuthenticator Message-Authenticator on Access-Requests ({@code access.message-authenticator},
 *     default {@code required}: the BlastRADIUS mitigation); requests with EAP always need it
 */
public record NasClient(
        String name,
        int id,
        int network,
        int prefixLength,
        byte[] secret,
        String vendor,
        MessageAuthenticatorPolicy messageAuthenticator,
        Identity[] identity,
        int idleTimeoutMinutes,
        MessageAuthenticatorPolicy accessMessageAuthenticator) {

    /** With Message-Authenticator required on Access-Requests. */
    public NasClient(
            String name,
            int id,
            int network,
            int prefixLength,
            byte[] secret,
            String vendor,
            MessageAuthenticatorPolicy messageAuthenticator,
            Identity[] identity,
            int idleTimeoutMinutes) {
        this(
                name,
                id,
                network,
                prefixLength,
                secret,
                vendor,
                messageAuthenticator,
                identity,
                idleTimeoutMinutes,
                MessageAuthenticatorPolicy.REQUIRED);
    }

    /** Without an idle timeout of its own. */
    public NasClient(
            String name,
            int id,
            int network,
            int prefixLength,
            byte[] secret,
            String vendor,
            MessageAuthenticatorPolicy messageAuthenticator,
            Identity[] identity) {
        this(name, id, network, prefixLength, secret, vendor, messageAuthenticator, identity, 0);
    }

    /** A NAS identified by its source address alone. */
    public NasClient(
            String name,
            int id,
            int network,
            int prefixLength,
            byte[] secret,
            String vendor,
            MessageAuthenticatorPolicy messageAuthenticator) {
        this(name, id, network, prefixLength, secret, vendor, messageAuthenticator, new Identity[0]);
    }

    /** A request attribute that identifies a device behind a NAS entry ({@code nas.<name>.identity}). */
    public enum Identity {
        /** NAS-Identifier (32), as sent */
        NAS_IDENTIFIER("nas-identifier"),
        /** the MAC address in Called-Station-Id (30), normalised; the {@code :SSID} suffix is dropped */
        CALLED_STATION_ID("called-station-id"),
        /** NAS-IP-Address (4) */
        NAS_IP_ADDRESS("nas-ip-address");

        private final String configName;

        Identity(String configName) {
            this.configName = configName;
        }

        public String configName() {
            return configName;
        }
    }

    /** Whether devices behind this entry are told apart by attributes. */
    public boolean identifiesDevices() {
        return identity.length > 0;
    }

    /** Hash of the identity setting; gateways must agree on it (the cluster counts mismatches). */
    public int identityFingerprint() {
        int h = 17;
        for (Identity i : identity) {
            h = h * 31 + i.ordinal() + 1;
        }
        return h;
    }

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
