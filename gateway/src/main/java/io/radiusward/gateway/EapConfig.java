/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

/**
 * EAP on the gateway ({@code auth.eap.*}, ADR 0026).
 *
 * @param methods the EAP methods offered, in order of preference ({@code auth.eap.methods}); a peer may ask for
 *     another of them with a Nak
 * @param timeout how long a conversation waits for the peer's next response
 * @param conversations conversations held at once; beyond it new ones are not answered
 * @param maxRounds round trips a conversation may take
 */
record EapConfig(List<String> methods, Duration timeout, int conversations, int maxRounds) {

    static final List<String> KNOWN = List.of("md5");

    static final EapConfig DEFAULT = new EapConfig(List.of("md5"), Duration.ofSeconds(30), 10_000, 50);

    static EapConfig from(Config config) {
        List<String> methods = config.list("auth.eap.methods", List.of("md5")).stream()
                .map(m -> m.trim().toLowerCase(Locale.ROOT))
                .toList();
        for (String m : methods) {
            if (!KNOWN.contains(m)) {
                throw new ConfigException("auth.eap.methods: unknown method " + m + " (known: " + KNOWN + ")");
            }
        }
        int conversations = config.integer("auth.eap.conversations", 10_000);
        if (conversations < 1) {
            throw new ConfigException("auth.eap.conversations: at least 1");
        }
        return new EapConfig(
                List.copyOf(methods), config.duration("auth.eap.timeout", Duration.ofSeconds(30)), conversations, 50);
    }

    /** The EAP type number of a method name. */
    static int type(String method) {
        return switch (method) {
            case "md5" -> EapPacket.TYPE_MD5;
            default -> -1;
        };
    }

    /** A fresh method object for a conversation, or {@code null} for an unknown type. */
    static EapMethod create(int type) {
        return switch (type) {
            case EapPacket.TYPE_MD5 -> new EapMd5();
            default -> null;
        };
    }
}
