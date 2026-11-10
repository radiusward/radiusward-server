/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.nio.charset.StandardCharsets;

/**
 * EAP-SIM, EAP-AKA and EAP-AKA′ settings ({@code auth.eap.sim.*}, {@code auth.eap.aka-prime.*}; ADR 0061).
 *
 * @param networkName EAP-AKA′'s network name, bound into its keys ({@code auth.eap.aka-prime.network.name}; "WLAN"
 *     for Wi-Fi access, 3GPP TS 24.302)
 */
record SimConfig(byte[] networkName) {

    static final SimConfig DEFAULT = new SimConfig("WLAN".getBytes(StandardCharsets.US_ASCII));

    static SimConfig from(Config config) {
        byte[] name = config.string("auth.eap.aka-prime.network.name", "WLAN").getBytes(StandardCharsets.UTF_8);
        if (name.length == 0 || name.length > 255) {
            throw new ConfigException("auth.eap.aka-prime.network.name: 1 to 255 bytes");
        }
        return new SimConfig(name);
    }
}
