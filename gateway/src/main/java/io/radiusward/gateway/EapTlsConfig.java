/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * The TLS side of EAP-TLS, PEAP and TTLS ({@code auth.eap.tls.*}, ADR 0028, 0033): the server's certificate chain and
 * key (PEM), the CAs that client certificates must chain to, their revocation check, the TLS versions, the EAP
 * fragment size, how a client certificate relates to the EAP identity.
 *
 * @param context the server's TLS material, reloaded when its files change
 * @param versions enabled TLS versions ({@code auth.eap.tls.versions}, default TLS 1.2 and 1.3)
 * @param fragmentSize largest TLS payload per EAP message ({@code auth.eap.tls.fragment.size}, RFC 5216 §2.1.5)
 * @param maxMessage largest TLS message a peer may send in fragments ({@code auth.eap.tls.max.message})
 * @param requireUser whether an EAP-TLS user must exist in an identity store; by default a valid client certificate
 *     is enough ({@code auth.eap.tls.require.user})
 * @param identity how the EAP identity must relate to the client certificate ({@code auth.eap.tls.identity})
 */
record EapTlsConfig(
        TlsCredentials context,
        List<String> versions,
        int fragmentSize,
        int maxMessage,
        boolean requireUser,
        CertificateIdentity.Check identity) {

    EapTlsConfig(TlsCredentials context, List<String> versions, int fragmentSize, int maxMessage, boolean requireUser) {
        this(context, versions, fragmentSize, maxMessage, requireUser, CertificateIdentity.Check.MATCH);
    }

    /** {@code null} when no certificate is configured. */
    static EapTlsConfig from(Config config) {
        String certificate = config.string("auth.eap.tls.certificate", "");
        if (certificate.isBlank()) {
            return null;
        }
        Path chain = Path.of(certificate);
        Path key = Path.of(config.string("auth.eap.tls.key"));
        String ca = config.string("auth.eap.tls.ca", "");
        List<String> versions = config.list("auth.eap.tls.versions", List.of("TLSv1.2", "TLSv1.3"));
        for (String v : versions) {
            if (!v.equals("TLSv1.2") && !v.equals("TLSv1.3")) {
                throw new ConfigException("auth.eap.tls.versions: TLSv1.2 and/or TLSv1.3, got " + v);
            }
        }
        int fragment = config.integer("auth.eap.tls.fragment.size", 1024);
        if (fragment < 64 || fragment > 3000) {
            throw new ConfigException("auth.eap.tls.fragment.size: 64 to 3000, got " + fragment);
        }
        TlsCredentials credentials = TlsCredentials.from(
                config,
                "auth.eap.tls.",
                chain,
                key,
                ca,
                config.duration("auth.eap.tls.session.timeout", Duration.ofHours(1)));
        return new EapTlsConfig(
                credentials,
                List.copyOf(versions),
                fragment,
                config.integer("auth.eap.tls.max.message", 65_536),
                config.bool("auth.eap.tls.require.user", false),
                choice(
                        CertificateIdentity.Check.class,
                        "auth.eap.tls.identity",
                        config.string("auth.eap.tls.identity", "match")));
    }

    /** A context from these files, without revocation checks or reloading (tests, tools). */
    static TlsCredentials context(Path chainFile, Path keyFile, Path caFile) {
        return new TlsCredentials(
                chainFile, keyFile, caFile, List.of(), TlsCredentials.Revocation.NONE, null, false, Duration.ZERO);
    }

    static <E extends Enum<E>> E choice(Class<E> type, String key, String value) {
        try {
            return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ConfigException(key + ": one of "
                    + Arrays.stream(type.getEnumConstants())
                            .map(c -> c.name().toLowerCase(Locale.ROOT))
                            .toList()
                    + ", got " + value);
        }
    }

    /** An unencrypted PKCS#8 key ({@code BEGIN PRIVATE KEY}): RSA, EC or EdDSA. */
    static PrivateKey privateKey(Path pem, String setting) throws IOException, GeneralSecurityException {
        String text = Files.readString(pem, StandardCharsets.US_ASCII);
        int begin = text.indexOf("-----BEGIN PRIVATE KEY-----");
        int end = text.indexOf("-----END PRIVATE KEY-----");
        if (begin < 0 || end < begin) {
            throw new ConfigException(setting + ": " + pem + " needs an unencrypted PKCS#8 key (BEGIN PRIVATE"
                    + " KEY); convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem");
        }
        byte[] der = Base64.getMimeDecoder().decode(text.substring(begin + 27, end));
        for (String algorithm : List.of("RSA", "EC", "Ed25519", "Ed448")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
            } catch (GeneralSecurityException e) {
                // not this algorithm
            }
        }
        throw new ConfigException(setting + ": " + pem + " holds no RSA, EC or EdDSA key");
    }
}
