/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.units;

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
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Certificates and keys as settings name them, PEM files, read the same way by the server, the sinks and the identity
 * stores: certificate chains and CA bundles, unencrypted PKCS#8 keys (RSA, EC, EdDSA), and TLS contexts built from
 * them.
 */
public final class Pem {

    private static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_KEY = "-----END PRIVATE KEY-----";

    private Pem() {}

    /** The certificates of a PEM file, in its order (a chain: the certificate first). */
    public static List<? extends Certificate> certificates(Path pem) throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(pem)) {
            return List.copyOf(CertificateFactory.getInstance("X.509").generateCertificates(in));
        }
    }

    /**
     * An unencrypted PKCS#8 key ({@code BEGIN PRIVATE KEY}): RSA, EC or EdDSA.
     *
     * @throws IllegalArgumentException for another format or algorithm, saying how to convert a key
     */
    public static PrivateKey privateKey(Path pem) throws IOException {
        String text = Files.readString(pem, StandardCharsets.US_ASCII);
        int begin = text.indexOf(BEGIN_KEY);
        int end = text.indexOf(END_KEY);
        if (begin < 0 || end < begin) {
            throw new IllegalArgumentException(pem + " needs an unencrypted PKCS#8 key (BEGIN PRIVATE KEY);"
                    + " convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem");
        }
        byte[] der = Base64.getMimeDecoder().decode(text.substring(begin + BEGIN_KEY.length(), end));
        for (String algorithm : List.of("RSA", "EC", "Ed25519", "Ed448")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
            } catch (GeneralSecurityException e) {
                // not this algorithm
            }
        }
        throw new IllegalArgumentException(pem + " holds no RSA, EC or EdDSA key");
    }

    /** A key store trusting the certificates of a PEM file (possibly none). */
    public static KeyStore trustStore(Path ca) throws IOException, GeneralSecurityException {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        int n = 0;
        for (Certificate c : certificates(ca)) {
            trust.setCertificateEntry("ca-" + n++, c);
        }
        return trust;
    }

    /**
     * A client context for {@code protocol} ({@code TLS} or {@code DTLS}): our certificate and key when both are given,
     * and the CAs the server must chain to.
     *
     * @throws IllegalArgumentException for a key that cannot be read ({@link #privateKey})
     */
    public static SSLContext clientContext(String protocol, Path certificate, Path key, Path ca)
            throws IOException, GeneralSecurityException {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        if (certificate != null && key != null) {
            keys.setKeyEntry(
                    "client",
                    privateKey(key),
                    new char[0],
                    certificates(certificate).toArray(Certificate[]::new));
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, new char[0]);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore(ca));
        SSLContext context = SSLContext.getInstance(protocol);
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }
}
