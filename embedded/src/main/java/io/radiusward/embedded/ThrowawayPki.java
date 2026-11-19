/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A CA made at start and gone on close, with the RADIUS server's certificate and client certificates on request, for
 * the TLS-based EAP methods. P-256 keys, valid for a day; the files are PEM in the embedded server's directory, read by
 * the server as an operator's would be ({@code auth.eap.tls.certificate}, {@code .key}, {@code .ca}).
 */
final class ThrowawayPki {

    static final String SERVER_NAME = "radiusward.embedded";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path dir;
    private final KeyPair caKeys;
    private final X509Certificate ca;

    private ThrowawayPki(Path dir, KeyPair caKeys, X509Certificate ca) {
        this.dir = dir;
        this.caKeys = caKeys;
        this.ca = ca;
    }

    static ThrowawayPki create(Path dir) {
        try {
            Files.createDirectories(dir);
            KeyPair caKeys = keys();
            X509Certificate ca = issue("CN=radiusward embedded CA", caKeys, null, null, true, null);
            ThrowawayPki pki = new ThrowawayPki(dir, caKeys, ca);
            KeyPair serverKeys = keys();
            X509Certificate server =
                    issue("CN=" + SERVER_NAME, serverKeys, caKeys, ca, false, KeyPurposeId.id_kp_serverAuth);
            write(dir.resolve("ca.pem"), "CERTIFICATE", ca.getEncoded());
            write(dir.resolve("server.pem"), "CERTIFICATE", server.getEncoded(), ca.getEncoded());
            write(
                    dir.resolve("server.key"),
                    "PRIVATE KEY",
                    serverKeys.getPrivate().getEncoded());
            return pki;
        } catch (GeneralSecurityException | OperatorCreationException | CertIOException e) {
            throw new IllegalStateException("cannot create the throwaway CA", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The server's certificate chain and key, and the CA client certificates must chain to. */
    Map<String, String> settings() {
        return Map.of(
                "auth.eap.tls.certificate", dir.resolve("server.pem").toString(),
                "auth.eap.tls.key", dir.resolve("server.key").toString(),
                "auth.eap.tls.ca", dir.resolve("ca.pem").toString());
    }

    X509Certificate ca() {
        return ca;
    }

    ClientCertificate client(String name) {
        try {
            KeyPair keys = keys();
            X509Certificate certificate =
                    issue("CN=" + name.replace(",", "\\,"), keys, caKeys, ca, false, KeyPurposeId.id_kp_clientAuth);
            return new ClientCertificate(name, keys.getPrivate(), certificate);
        } catch (GeneralSecurityException | OperatorCreationException | CertIOException e) {
            throw new IllegalStateException("cannot issue a client certificate for " + name, e);
        }
    }

    private static KeyPair keys() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    private static X509Certificate issue(
            String subject,
            KeyPair keys,
            KeyPair issuerKeys,
            X509Certificate issuer,
            boolean isCa,
            KeyPurposeId purpose)
            throws GeneralSecurityException, OperatorCreationException, CertIOException {
        Instant now = Instant.now();
        X500Name name = new X500Name(subject);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuer == null
                        ? name
                        : X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
                new BigInteger(64, RANDOM).add(BigInteger.ONE),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(1, ChronoUnit.DAYS)),
                name,
                keys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        if (isCa) {
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } else {
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
        }
        if (purpose == KeyPurposeId.id_kp_serverAuth) {
            b.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, SERVER_NAME)));
        }
        KeyPair signer = issuerKeys == null ? keys : issuerKeys;
        return new JcaX509CertificateConverter()
                .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
    }

    private static void write(Path file, String type, byte[]... ders) throws IOException {
        StringBuilder pem = new StringBuilder();
        for (byte[] der : ders) {
            pem.append("-----BEGIN ")
                    .append(type)
                    .append("-----\n")
                    .append(Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(der))
                    .append("\n-----END ")
                    .append(type)
                    .append("-----\n");
        }
        Files.writeString(file, pem);
    }
}
