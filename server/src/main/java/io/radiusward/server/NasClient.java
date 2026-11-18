/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

/**
 * A configured NAS ({@code nas.<name>.*}).
 *
 * @param name configuration name
 * @param id stable identity used in event keys; the same on every gateway (FNV-1a of the name unless
 *     {@code nas.<name>.id} is set)
 * @param network IPv4 network address as an int
 * @param prefixLength CIDR prefix length, 32 for a single address (128 for a single IPv6 address)
 * @param secret shared secret bytes
 * @param vendor vendor profile name (informational in Phase 1)
 * @param messageAuthenticator {@code required}, {@code optional} or {@code off}
 * @param identity attributes telling apart the devices behind this entry (NAT), first present wins; empty: the
 *     source address is the device ({@code source-ip}, the default)
 * @param idleTimeoutMinutes a session of this entry without an event for this long is closed (lost Stop); about three
 *     interim intervals. 0: the cluster's {@code service.idle.timeout}
 * @param accessMessageAuthenticator Message-Authenticator on Access-Requests ({@code access.message-authenticator},
 *     default {@code required}: the BlastRADIUS mitigation); requests with EAP always need it
 * @param network6 the IPv6 network (16 bytes) of an IPv6 entry, {@code null} for IPv4 (ADR 0047)
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
        MessageAuthenticatorPolicy accessMessageAuthenticator,
        byte[] network6) {

    /** Whether it is an IPv6 entry: {@link #network6()} and a prefix length up to 128 (ADR 0047). */
    public boolean ipv6() {
        return network6 != null;
    }

    /** Whether it covers exactly one address: /32, or /128 for IPv6. */
    public boolean singleAddress() {
        return ipv6() ? prefixLength == 128 : prefixLength == 32;
    }

    /** Whether this IPv6 entry covers the address (16 bytes). */
    public boolean matches6(byte[] address) {
        if (network6 == null || address.length != 16) {
            return false;
        }
        int full = prefixLength / 8;
        for (int i = 0; i < full; i++) {
            if (address[i] != network6[i]) {
                return false;
            }
        }
        int rest = prefixLength % 8;
        if (rest == 0) {
            return true;
        }
        int mask = (0xFF << (8 - rest)) & 0xFF;
        return (address[full] & mask) == (network6[full] & mask);
    }

    /** The same entry with another shared secret (its RadSec or DTLS secret). */
    public NasClient withSecret(byte[] otherSecret) {
        return new NasClient(
                name,
                id,
                network,
                prefixLength,
                otherSecret,
                vendor,
                messageAuthenticator,
                identity,
                idleTimeoutMinutes,
                accessMessageAuthenticator,
                network6);
    }

    /** An entry with every setting at its {@code nas.<name>.*} default but the address and the secret. */
    public static Builder builder(String name, int id) {
        return new Builder(name, id);
    }

    public static final class Builder {
        private final String name;
        private final int id;
        private int network;
        private int prefixLength = 32;
        private byte[] network6;
        private byte[] secret = new byte[0];
        private String vendor = "default";
        private MessageAuthenticatorPolicy messageAuthenticator = MessageAuthenticatorPolicy.OPTIONAL;
        private Identity[] identity = new Identity[0];
        private int idleTimeoutMinutes;
        private MessageAuthenticatorPolicy accessMessageAuthenticator = MessageAuthenticatorPolicy.REQUIRED;

        private Builder(String name, int id) {
            this.name = name;
            this.id = id;
        }

        /** An IPv4 network: address as an int and prefix length (32 for one address, the default). */
        public Builder network(int network, int prefixLength) {
            this.network = network;
            this.prefixLength = prefixLength;
            this.network6 = null;
            return this;
        }

        /** An IPv6 network (16 bytes) and prefix length. */
        public Builder network6(byte[] network6, int prefixLength) {
            this.network6 = network6.clone();
            this.prefixLength = prefixLength;
            return this;
        }

        public Builder secret(byte[] secret) {
            this.secret = secret;
            return this;
        }

        public Builder vendor(String vendor) {
            this.vendor = vendor;
            return this;
        }

        /** On accounting requests; default optional. */
        public Builder messageAuthenticator(MessageAuthenticatorPolicy policy) {
            this.messageAuthenticator = policy;
            return this;
        }

        /** The attributes that tell devices behind the entry apart; default none. */
        public Builder identity(Identity... identity) {
            this.identity = identity;
            return this;
        }

        public Builder idleTimeoutMinutes(int minutes) {
            this.idleTimeoutMinutes = minutes;
            return this;
        }

        /** On Access-Requests; default required (the BlastRADIUS mitigation). */
        public Builder accessMessageAuthenticator(MessageAuthenticatorPolicy policy) {
            this.accessMessageAuthenticator = policy;
            return this;
        }

        public NasClient build() {
            return new NasClient(
                    name,
                    id,
                    network,
                    prefixLength,
                    secret,
                    vendor,
                    messageAuthenticator,
                    identity,
                    idleTimeoutMinutes,
                    accessMessageAuthenticator,
                    network6);
        }
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

    /**
     * An entry without an address, identified over RadSec by its client certificate alone (ADR 0034): never matched
     * by a source address, so never reached over UDP.
     */
    public boolean certificateOnly() {
        return prefixLength < 0;
    }

    public boolean matches(int address) {
        return network6 == null && (address & mask()) == (network & mask());
    }
}
