/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * EAP-SIM, EAP-AKA and EAP-AKA′ settings ({@code auth.eap.sim.*}, {@code auth.eap.aka-prime.*}; ADR 0061).
 *
 * @param networkName EAP-AKA′'s network name, bound into its keys ({@code auth.eap.aka-prime.network.name}; "WLAN"
 *     for Wi-Fi access, 3GPP TS 24.302)
 * @param identities pseudonyms and fast re-authentication
 */
record SimConfig(byte[] networkName, SimIdentities identities) {

    static final SimConfig DEFAULT = new SimConfig("WLAN".getBytes(StandardCharsets.US_ASCII), SimIdentities.NONE);

    static SimConfig from(Config config) {
        byte[] name = config.string("auth.eap.aka-prime.network.name", "WLAN").getBytes(StandardCharsets.UTF_8);
        if (name.length == 0 || name.length > 255) {
            throw new ConfigException("auth.eap.aka-prime.network.name: 1 to 255 bytes");
        }
        List<SimIdentities.Key> keys = new ArrayList<>();
        for (String raw : config.list("auth.eap.sim.pseudonym.keys", List.of())) {
            String k = raw.trim();
            int colon = k.indexOf(':');
            if (colon != 1 || !Character.isLetterOrDigit(k.charAt(0))) {
                throw new ConfigException(
                        "auth.eap.sim.pseudonym.keys: <id>:<32 hex digits>, the id one letter or digit");
            }
            byte[] aes;
            try {
                aes = HexFormat.of().parseHex(k.substring(2));
            } catch (IllegalArgumentException e) {
                aes = new byte[0];
            }
            if (aes.length != 16) {
                throw new ConfigException(
                        "auth.eap.sim.pseudonym.keys: key " + k.charAt(0) + " is not 16 bytes of hex");
            }
            if (keys.stream().anyMatch(x -> x.id() == k.charAt(0))) {
                throw new ConfigException("auth.eap.sim.pseudonym.keys: key id " + k.charAt(0) + " twice");
            }
            keys.add(new SimIdentities.Key(k.charAt(0), aes));
        }
        Duration lifetime = config.duration("auth.eap.sim.reauth.lifetime", Duration.ofHours(1));
        int max = config.integer("auth.eap.sim.reauth.max", 16);
        int sessions = config.integer("auth.eap.sim.reauth.sessions", 100_000);
        if (max < 0 || max > 0xFFFF || sessions < 1) {
            throw new ConfigException("auth.eap.sim.reauth.max: 0 to 65535; auth.eap.sim.reauth.sessions: at least 1");
        }
        return new SimConfig(name, new SimIdentities(keys, lifetime, max, sessions, System::currentTimeMillis));
    }
}
