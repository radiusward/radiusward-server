/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import com.sun.net.httpserver.HttpServer;
import java.math.BigInteger;
import java.net.InetSocketAddress;
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
import java.util.Set;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/** Test certificates (Bouncy Castle, test scope only): a CA, a server and client certificates, as PEM files. */
final class TestPki {

    record Issued(KeyPair keys, X509Certificate certificate) {}

    private static final java.util.concurrent.atomic.AtomicLong SERIALS = new java.util.concurrent.atomic.AtomicLong();

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

    /** A client certificate with subject alternative names. */
    Issued client(String commonName, GeneralName... alternativeNames) throws Exception {
        return issue("CN=" + commonName, ca, false, KeyPurposeId.id_kp_clientAuth, alternativeNames);
    }

    /** The Microsoft UPN otherName of a certificate's subject alternative names. */
    static GeneralName upn(String upn) {
        return new GeneralName(GeneralName.otherName, new DERSequence(new ASN1Encodable[] {
            new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), new DERTaggedObject(true, 0, new DERUTF8String(upn))
        }));
    }

    /** A CRL of this CA listing {@code revoked}, valid for a day. */
    Path crl(Path file, Issued... revoked) throws Exception {
        Instant now = Instant.now();
        X509v2CRLBuilder b = new X509v2CRLBuilder(
                new X500Name(ca.certificate().getSubjectX500Principal().getName()),
                Date.from(now.minus(1, ChronoUnit.HOURS)));
        b.setNextUpdate(Date.from(now.plus(1, ChronoUnit.DAYS)));
        for (Issued r : revoked) {
            b.addCRLEntry(
                    r.certificate().getSerialNumber(),
                    Date.from(now.minus(1, ChronoUnit.MINUTES)),
                    CRLReason.keyCompromise);
        }
        X509CRLHolder crl = b.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(ca.keys().getPrivate()));
        return write(file, "X509 CRL", crl.getEncoded());
    }

    /**
     * An OCSP responder for this CA on localhost: responses signed by the CA, {@code revoked} serials revoked, all
     * others good. Answers GET and POST.
     */
    HttpServer ocspResponder(Set<BigInteger> revoked) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try {
                byte[] body = exchange.getRequestMethod().equals("GET")
                        ? Base64.getDecoder()
                                .decode(java.net.URLDecoder.decode(
                                        exchange.getRequestURI().getRawPath().substring(1), StandardCharsets.US_ASCII))
                        : exchange.getRequestBody().readAllBytes();
                OCSPReq request = new OCSPReq(body);
                BasicOCSPRespBuilder b = new JcaBasicOCSPRespBuilder(
                        ca.certificate().getPublicKey(),
                        new JcaDigestCalculatorProviderBuilder().build().get(RespID.HASH_SHA1));
                Date now = new Date();
                for (Req r : request.getRequestList()) {
                    CertificateID id = r.getCertID();
                    CertificateStatus status = revoked.contains(id.getSerialNumber())
                            ? new RevokedStatus(new Date(now.getTime() - 60_000), CRLReason.keyCompromise)
                            : CertificateStatus.GOOD;
                    b.addResponse(id, status, now, new Date(now.getTime() + 3_600_000), null);
                }
                org.bouncycastle.asn1.x509.Extension nonce =
                        request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                if (nonce != null) {
                    b.setResponseExtensions(new Extensions(nonce));
                }
                BasicOCSPResp basic = b.build(
                        new JcaContentSignerBuilder("SHA256withECDSA")
                                .build(ca.keys().getPrivate()),
                        new X509CertificateHolder[] {new JcaX509CertificateHolder(ca.certificate())},
                        now);
                byte[] out = new OCSPRespBuilder()
                        .build(OCSPRespBuilder.SUCCESSFUL, basic)
                        .getEncoded();
                exchange.getResponseHeaders().add("Content-Type", "application/ocsp-response");
                exchange.sendResponseHeaders(200, out.length);
                exchange.getResponseBody().write(out);
                ocspRequests.incrementAndGet();
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        });
        server.start();
        return server;
    }

    final java.util.concurrent.atomic.AtomicInteger ocspRequests = new java.util.concurrent.atomic.AtomicInteger();

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

    private static Issued issue(
            String subject, Issued issuer, boolean isCa, KeyPurposeId purpose, GeneralName... alternativeNames)
            throws Exception {
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
                BigInteger.valueOf(now.toEpochMilli()).shiftLeft(16).add(BigInteger.valueOf(SERIALS.incrementAndGet())),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(1, ChronoUnit.DAYS)),
                name,
                keys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        if (purpose != null) {
            b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
        }
        if (alternativeNames.length > 0) {
            b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(alternativeNames));
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
