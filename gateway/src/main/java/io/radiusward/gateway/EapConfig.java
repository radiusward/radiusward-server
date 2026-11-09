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
 * @param tls the TLS side ({@code auth.eap.tls.*}), {@code null} without a certificate
 */
record EapConfig(List<String> methods, Duration timeout, int conversations, int maxRounds, EapTlsConfig tls) {

    static final List<String> KNOWN = List.of("md5", "tls", "peap");

    static final EapConfig DEFAULT = new EapConfig(List.of("md5"), Duration.ofSeconds(30), 10_000, 50, null);

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
        EapTlsConfig tls = EapTlsConfig.from(config);
        if ((methods.contains("tls") || methods.contains("peap")) && tls == null) {
            throw new ConfigException(
                    "auth.eap.methods: tls and peap need auth.eap.tls.certificate and auth.eap.tls.key");
        }
        if (methods.contains("tls") && config.string("auth.eap.tls.ca", "").isBlank()) {
            throw new ConfigException("auth.eap.methods: tls needs auth.eap.tls.ca, the CAs of client certificates");
        }
        return new EapConfig(
                List.copyOf(methods),
                config.duration("auth.eap.timeout", Duration.ofSeconds(30)),
                conversations,
                200, // a TLS handshake in small fragments takes many rounds
                tls);
    }

    /** The EAP type number of a method name. */
    static int type(String method) {
        return switch (method) {
            case "md5" -> EapPacket.TYPE_MD5;
            case "tls" -> EapTls.TYPE;
            case "peap" -> Peap.TYPE;
            default -> -1;
        };
    }

    /** A fresh method object for a conversation, or {@code null} for an unknown type. */
    EapMethod create(int type) {
        return switch (type) {
            case EapPacket.TYPE_MD5 -> new EapMd5();
            case EapTls.TYPE -> tls == null ? null : new EapTls(tls);
            case Peap.TYPE -> tls == null ? null : new Peap(tls);
            default -> null;
        };
    }

    /**
     * Whether the outer identity needs no store entry: EAP-TLS, where the certificate is the credential (unless
     * {@code require.user}), and tunnels, whose outer identity is often anonymous and whose inner one is checked.
     */
    boolean outerOptional(int type) {
        return (type == EapTls.TYPE && tls != null && !tls.requireUser()) || type == Peap.TYPE;
    }
}
