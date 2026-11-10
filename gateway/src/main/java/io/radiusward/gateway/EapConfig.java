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
 * @param ttlsInner the EAP types TTLS offers when the client starts EAP inside, first preferred
 *     ({@code auth.eap.ttls.inner}, ADR 0040)
 * @param teapInner TEAP's inner methods, first preferred: EAP types, or {@link Teap#BASIC} for Basic-Password-Auth
 *     ({@code auth.eap.teap.inner}, ADR 0041)
 * @param teapAuthorityId TEAP's Authority-ID ({@code auth.eap.teap.authority.id})
 * @param teapIdentity the identity types TEAP asks for in turn ({@code auth.eap.teap.identity}); empty: any
 * @param pwdServerId EAP-pwd's server identity ({@code auth.eap.pwd.server.id}, ADR 0042)
 */
record EapConfig(
        List<String> methods,
        Duration timeout,
        int conversations,
        int maxRounds,
        EapTlsConfig tls,
        List<Integer> peapInner,
        Peap.Binding peapBinding,
        boolean peapClientCertificate,
        List<Integer> ttlsInner,
        List<Integer> teapInner,
        byte[] teapAuthorityId,
        List<Integer> teapIdentity,
        byte[] pwdServerId) {

    EapConfig(
            List<String> methods,
            Duration timeout,
            int conversations,
            int maxRounds,
            EapTlsConfig tls,
            List<Integer> peapInner,
            Peap.Binding peapBinding,
            boolean peapClientCertificate,
            List<Integer> ttlsInner) {
        this(
                methods,
                timeout,
                conversations,
                maxRounds,
                tls,
                peapInner,
                peapBinding,
                peapClientCertificate,
                ttlsInner,
                DEFAULT_TEAP_INNER,
                DEFAULT_AUTHORITY_ID,
                List.of(),
                DEFAULT_AUTHORITY_ID);
    }

    static final List<Integer> DEFAULT_TEAP_INNER = List.of(InnerEap.MS_CHAP_V2, InnerEap.GTC, InnerEap.MD5);
    static final byte[] DEFAULT_AUTHORITY_ID = "radiusward".getBytes(java.nio.charset.StandardCharsets.UTF_8);

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
        this(methods, timeout, conversations, maxRounds, tls, peapInner, peapBinding, false, DEFAULT_TTLS_INNER);
    }

    static final List<Integer> DEFAULT_TTLS_INNER = List.of(InnerEap.MS_CHAP_V2, InnerEap.GTC, InnerEap.MD5);

    static final List<String> KNOWN = List.of("md5", "tls", "peap", "ttls", "teap", "pwd");

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
        if ((methods.contains("tls")
                        || methods.contains("peap")
                        || methods.contains("ttls")
                        || methods.contains("teap"))
                && tls == null) {
            throw new ConfigException(
                    "auth.eap.methods: tls, peap, ttls and teap need auth.eap.tls.certificate and auth.eap.tls.key");
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
        List<Integer> ttlsInner = config.list("auth.eap.ttls.inner", List.of("mschapv2", "gtc", "md5")).stream()
                .map(m -> switch (m.trim().toLowerCase(Locale.ROOT)) {
                    case "mschapv2" -> InnerEap.MS_CHAP_V2;
                    case "gtc" -> InnerEap.GTC;
                    case "md5" -> InnerEap.MD5;
                    default ->
                        throw new ConfigException(
                                "auth.eap.ttls.inner: unknown inner EAP method " + m + " (mschapv2, gtc, md5)");
                })
                .toList();
        List<Integer> teapInner = config.list("auth.eap.teap.inner", List.of("mschapv2", "gtc", "md5")).stream()
                .map(m -> switch (m.trim().toLowerCase(Locale.ROOT)) {
                    case "mschapv2" -> InnerEap.MS_CHAP_V2;
                    case "gtc" -> InnerEap.GTC;
                    case "md5" -> InnerEap.MD5;
                    case "tls" -> InnerEap.TLS;
                    case "basic" -> Teap.BASIC;
                    default ->
                        throw new ConfigException(
                                "auth.eap.teap.inner: unknown inner method " + m + " (mschapv2, gtc, md5, tls, basic)");
                })
                .toList();
        if (teapInner.isEmpty()) {
            throw new ConfigException("auth.eap.teap.inner: at least one inner method");
        }
        if (teapInner.contains(InnerEap.TLS)
                && config.string("auth.eap.tls.ca", "").isBlank()) {
            throw new ConfigException("auth.eap.teap.inner: tls needs auth.eap.tls.ca, the CAs of client certificates");
        }
        List<Integer> teapIdentity = config.list("auth.eap.teap.identity", List.of()).stream()
                .map(m -> switch (m.trim().toLowerCase(Locale.ROOT)) {
                    case "user" -> Teap.USER;
                    case "machine" -> Teap.MACHINE;
                    default ->
                        throw new ConfigException(
                                "auth.eap.teap.identity: user and/or machine, in the order asked, got " + m);
                })
                .toList();
        if (teapIdentity.size() > 2 || teapIdentity.stream().distinct().count() != teapIdentity.size()) {
            throw new ConfigException("auth.eap.teap.identity: user, machine, or both once each");
        }
        byte[] pwdServerId =
                config.string("auth.eap.pwd.server.id", "radiusward").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (pwdServerId.length == 0 || pwdServerId.length > 253) {
            throw new ConfigException("auth.eap.pwd.server.id: 1 to 253 bytes");
        }
        byte[] authorityId = config.string("auth.eap.teap.authority.id", "radiusward")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (authorityId.length == 0 || authorityId.length > 255) {
            throw new ConfigException("auth.eap.teap.authority.id: 1 to 255 bytes");
        }
        return new EapConfig(
                List.copyOf(methods),
                config.duration("auth.eap.timeout", Duration.ofSeconds(30)),
                conversations,
                200, // a TLS handshake in small fragments takes many rounds
                tls,
                inner,
                peapBinding,
                peapCertificate,
                ttlsInner,
                teapInner,
                authorityId,
                teapIdentity,
                pwdServerId);
    }

    /** The EAP type number of a method name. */
    static int type(String method) {
        return switch (method) {
            case "md5" -> EapPacket.TYPE_MD5;
            case "tls" -> EapTls.TYPE;
            case "peap" -> Peap.TYPE;
            case "ttls" -> Ttls.TYPE;
            case "teap" -> Teap.TYPE;
            case "pwd" -> EapPwd.TYPE;
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
            case Ttls.TYPE -> tls == null ? null : new Ttls(tls, ttlsInner);
            case Teap.TYPE -> tls == null ? null : new Teap(tls, teapInner, teapAuthorityId, teapIdentity);
            case EapPwd.TYPE -> new EapPwd(pwdServerId);
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
                || type == Ttls.TYPE
                || type == Teap.TYPE;
    }
}
