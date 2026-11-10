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
 * @param peapInner the inner EAP types PEAP offers, first preferred ({@code auth.eap.peap.inner})
 * @param peapBinding PEAP crypto-binding ({@code auth.eap.peap.crypto.binding}, ADR 0032)
 * @param peapClientCertificate whether PEAP's TLS handshake requires a client certificate
 *     ({@code auth.eap.peap.client.certificate}, ADR 0039)
 */
record EapConfig(
        List<String> methods,
        Duration timeout,
        int conversations,
        int maxRounds,
        EapTlsConfig tls,
        List<Integer> peapInner,
        Peap.Binding peapBinding,
        boolean peapClientCertificate) {

    EapConfig(List<String> methods, Duration timeout, int conversations, int maxRounds, EapTlsConfig tls) {
        this(methods, timeout, conversations, maxRounds, tls, List.of(Peap.MS_CHAP_V2), Peap.Binding.OPTIONAL);
    }

    EapConfig(
            List<String> methods,
            Duration timeout,
            int conversations,
            int maxRounds,
            EapTlsConfig tls,
            List<Integer> peapInner,
            Peap.Binding peapBinding) {
        this(methods, timeout, conversations, maxRounds, tls, peapInner, peapBinding, false);
    }

    static final List<String> KNOWN = List.of("md5", "tls", "peap", "ttls");

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
        if ((methods.contains("tls") || methods.contains("peap") || methods.contains("ttls")) && tls == null) {
            throw new ConfigException(
                    "auth.eap.methods: tls, peap and ttls need auth.eap.tls.certificate and auth.eap.tls.key");
        }
        if (methods.contains("tls") && config.string("auth.eap.tls.ca", "").isBlank()) {
            throw new ConfigException("auth.eap.methods: tls needs auth.eap.tls.ca, the CAs of client certificates");
        }
        List<Integer> inner = config.list("auth.eap.peap.inner", List.of("mschapv2")).stream()
                .map(m -> switch (m.trim().toLowerCase(Locale.ROOT)) {
                    case "mschapv2" -> Peap.MS_CHAP_V2;
                    case "gtc" -> Peap.GTC;
                    case "tls" -> EapTls.TYPE;
                    default ->
                        throw new ConfigException(
                                "auth.eap.peap.inner: unknown inner method " + m + " (mschapv2, gtc, tls)");
                })
                .toList();
        if (inner.contains(EapTls.TYPE) && config.string("auth.eap.tls.ca", "").isBlank()) {
            throw new ConfigException("auth.eap.peap.inner: tls needs auth.eap.tls.ca, the CAs of client certificates");
        }
        String binding =
                config.string("auth.eap.peap.crypto.binding", "optional").trim();
        Peap.Binding peapBinding;
        try {
            peapBinding = Peap.Binding.valueOf(binding.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ConfigException("auth.eap.peap.crypto.binding: off, optional or required, got " + binding, e);
        }
        boolean peapCertificate = config.bool("auth.eap.peap.client.certificate", false);
        if (peapCertificate && config.string("auth.eap.tls.ca", "").isBlank()) {
            throw new ConfigException(
                    "auth.eap.peap.client.certificate: needs auth.eap.tls.ca, the CAs of client certificates");
        }
        return new EapConfig(
                List.copyOf(methods),
                config.duration("auth.eap.timeout", Duration.ofSeconds(30)),
                conversations,
                200, // a TLS handshake in small fragments takes many rounds
                tls,
                inner,
                peapBinding,
                peapCertificate);
    }

    /** The EAP type number of a method name. */
    static int type(String method) {
        return switch (method) {
            case "md5" -> EapPacket.TYPE_MD5;
            case "tls" -> EapTls.TYPE;
            case "peap" -> Peap.TYPE;
            case "ttls" -> Ttls.TYPE;
            default -> -1;
        };
    }

    /**
     * A fresh method object for a conversation, or {@code null} for an unknown type.
     *
     * @param identity the peer's EAP identity
     */
    EapMethod create(int type, String identity) {
        return switch (type) {
            case EapPacket.TYPE_MD5 -> new EapMd5();
            case EapTls.TYPE -> tls == null ? null : new EapTls(tls, identity);
            case Peap.TYPE -> tls == null ? null : new Peap(tls, peapInner, peapBinding, peapClientCertificate);
            case Ttls.TYPE -> tls == null ? null : new Ttls(tls);
            default -> null;
        };
    }

    /**
     * Whether the outer identity needs no store entry: EAP-TLS, where the certificate is the credential (unless
     * {@code require.user}), and tunnels, whose outer identity is often anonymous and whose inner one is checked.
     */
    boolean outerOptional(int type) {
        return (type == EapTls.TYPE
                        && tls != null
                        && (!tls.requireUser() || tls.identity() == CertificateIdentity.Check.CERTIFICATE))
                || type == Peap.TYPE
                || type == Ttls.TYPE;
    }
}
