/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * The TLS side of EAP-TLS, PEAP and TTLS ({@code auth.eap.tls.*}, ADR 0028): the server's certificate chain and key
 * (PEM), the CAs that client certificates must chain to, the TLS versions, the EAP fragment size.
 *
 * @param context the JDK TLS context built from them
 * @param versions enabled TLS versions ({@code auth.eap.tls.versions}, default TLS 1.2 and 1.3)
 * @param fragmentSize largest TLS payload per EAP message ({@code auth.eap.tls.fragment.size}, RFC 5216 §2.1.5)
 * @param maxMessage largest TLS message a peer may send in fragments ({@code auth.eap.tls.max.message})
 * @param requireUser whether an EAP-TLS user must exist in an identity store; by default a valid client certificate
 *     is enough ({@code auth.eap.tls.require.user})
 */
record EapTlsConfig(SSLContext context, List<String> versions, int fragmentSize, int maxMessage, boolean requireUser) {

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
        return new EapTlsConfig(
                context(chain, key, ca.isBlank() ? null : Path.of(ca)),
                List.copyOf(versions),
                fragment,
                config.integer("auth.eap.tls.max.message", 65_536),
                config.bool("auth.eap.tls.require.user", false));
    }

    static SSLContext context(Path chainFile, Path keyFile, Path caFile) {
        try {
            Certificate[] chain = certificates(chainFile).toArray(Certificate[]::new);
            if (chain.length == 0) {
                throw new ConfigException("auth.eap.tls.certificate: no certificate in " + chainFile);
            }
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry("server", privateKey(keyFile), new char[0], chain);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keys, new char[0]);
            TrustManagerFactory tmf = null;
            if (caFile != null) {
                KeyStore trust = KeyStore.getInstance("PKCS12");
                trust.load(null, null);
                int n = 0;
                for (Certificate c : certificates(caFile)) {
                    trust.setCertificateEntry("ca-" + n++, c);
                }
                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trust);
            }
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), null);
            return context;
        } catch (IOException | GeneralSecurityException e) {
            throw new ConfigException("auth.eap.tls: " + e.getMessage(), e);
        }
    }

    static Collection<? extends Certificate> certificates(Path pem) throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(pem)) {
            return CertificateFactory.getInstance("X.509").generateCertificates(in);
        }
    }

    /** An unencrypted PKCS#8 key ({@code BEGIN PRIVATE KEY}): RSA, EC or EdDSA. */
    static PrivateKey privateKey(Path pem) throws IOException, GeneralSecurityException {
        String text = Files.readString(pem, StandardCharsets.US_ASCII);
        int begin = text.indexOf("-----BEGIN PRIVATE KEY-----");
        int end = text.indexOf("-----END PRIVATE KEY-----");
        if (begin < 0 || end < begin) {
            throw new ConfigException("auth.eap.tls.key: " + pem + " needs an unencrypted PKCS#8 key (BEGIN PRIVATE"
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
        throw new ConfigException("auth.eap.tls.key: " + pem + " holds no RSA, EC or EdDSA key");
    }
}
