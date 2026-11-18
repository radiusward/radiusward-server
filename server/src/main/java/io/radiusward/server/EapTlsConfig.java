/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.units.Pem;
import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.List;

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
                config.enumValue(
                        "auth.eap.tls.identity", CertificateIdentity.Check.class, CertificateIdentity.Check.MATCH));
    }

    /** A context from these files, without revocation checks or reloading (tests, tools). */
    static TlsCredentials context(Path chainFile, Path keyFile, Path caFile) {
        return new TlsCredentials(
                chainFile, keyFile, caFile, List.of(), TlsCredentials.Revocation.NONE, null, false, Duration.ZERO);
    }

    /** An unencrypted PKCS#8 key ({@link Pem#privateKey}); a configuration error naming {@code setting} otherwise. */
    static PrivateKey privateKey(Path pem, String setting) throws IOException {
        try {
            return Pem.privateKey(pem);
        } catch (IllegalArgumentException e) {
            throw new ConfigException(setting + ": " + e.getMessage(), e);
        }
    }
}
