/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Test certificates (Bouncy Castle, test scope only): a CA, a server and client certificates, as PEM files. */
final class TestPki {

    record Issued(KeyPair keys, X509Certificate certificate) {}

    final Issued ca;
    final Issued server;
    final Path caPem;
    final Path serverPem;
    final Path serverKey;

    TestPki(Path dir, String name) throws Exception {
        ca = issue("CN=" + name + " Test CA", null, true, null);
        server = issue("CN=radius." + name + ".test", ca, false, KeyPurposeId.id_kp_serverAuth);
        caPem = write(
                dir.resolve(name + "-ca.pem"), "CERTIFICATE", ca.certificate().getEncoded());
        serverPem = write(
                dir.resolve(name + "-server.pem"),
                "CERTIFICATE",
                server.certificate().getEncoded());
        serverKey = write(
                dir.resolve(name + "-server.key"),
                "PRIVATE KEY",
                server.keys().getPrivate().getEncoded());
    }

    Issued client(String commonName) throws Exception {
        return issue("CN=" + commonName, ca, false, KeyPurposeId.id_kp_clientAuth);
    }

    /** A TLS client context: its certificate (or none) and trust in {@code serverCa}. */
    static SSLContext clientContext(Issued client, Issued serverCa) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        if (client != null) {
            keys.setKeyEntry(
                    "client", client.keys().getPrivate(), new char[0], new X509Certificate[] {client.certificate()});
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, new char[0]);
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ca", serverCa.certificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    private static Issued issue(String subject, Issued issuer, boolean isCa, KeyPurposeId purpose) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        Instant now = Instant.now();
        X500Name name = new X500Name(subject);
        X500Name issuerName = issuer == null
                ? name
                : new X500Name(issuer.certificate().getSubjectX500Principal().getName());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerName,
                BigInteger.valueOf(now.toEpochMilli()).add(BigInteger.valueOf(System.nanoTime() & 0xFFFF)),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(1, ChronoUnit.DAYS)),
                name,
                keys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        if (purpose != null) {
            b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
        }
        if (purpose == KeyPurposeId.id_kp_serverAuth) {
            b.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, subject.substring(3))));
        }
        KeyPair signer = issuer == null ? keys : issuer.keys();
        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
        return new Issued(keys, certificate);
    }

    static Path write(Path file, String type, byte[] der) throws Exception {
        String pem = "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(der)
                + "\n-----END " + type + "-----\n";
        return Files.writeString(file, pem);
    }
}
