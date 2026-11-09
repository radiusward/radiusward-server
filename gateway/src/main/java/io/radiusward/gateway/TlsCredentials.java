/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The server's certificate, key, client CAs and revocation data for EAP (ADR 0028, 0033), as a JDK TLS context that is
 * rebuilt when one of the files changes: checked at most every {@code reload} interval, on the worker that starts a
 * handshake. A change that does not load (a certificate without its new key, a half-written file) keeps the previous
 * context and is retried at the next check.
 */
final class TlsCredentials {

    private static final Logger LOG = LogManager.getLogger(TlsCredentials.class);

    /** How client certificates are checked for revocation ({@code auth.eap.tls.revocation}). */
    enum Revocation {
        NONE,
        /** CRLs from {@code auth.eap.tls.crl}; every certificate of the chain needs its issuer's CRL. */
        CRL,
        /** OCSP (the certificate's responder, or {@code auth.eap.tls.ocsp.url}); CRLs as fallback if configured. */
        OCSP
    }

    private final String prefix;
    private final Duration sessionTimeout; // null: the JDK's default
    private final Path chain;
    private final Path key;
    private final Path ca;
    private final List<Path> crls;
    private final Revocation revocation;
    private final URI ocspResponder;
    private final boolean softFail;
    private final long checkEveryMillis;
    private final AtomicLong reloads = new AtomicLong();
    private final AtomicLong reloadFailures = new AtomicLong();
    private volatile SSLContext context;
    private volatile long nextCheck;
    private long[] stamps;

    /**
     * @param ca the client CAs, {@code null} when no client certificates are checked (PEAP, TTLS only)
     * @param reload how often the files are checked for changes; zero: never
     */
    TlsCredentials(
            Path chain,
            Path key,
            Path ca,
            List<Path> crls,
            Revocation revocation,
            URI ocspResponder,
            boolean softFail,
            Duration reload) {
        this("auth.eap.tls.", chain, key, ca, crls, revocation, ocspResponder, softFail, reload, null);
    }

    /** @param prefix the configuration keys these come from, for messages ({@code auth.eap.tls.}, {@code radsec.}) */
    TlsCredentials(
            String prefix,
            Path chain,
            Path key,
            Path ca,
            List<Path> crls,
            Revocation revocation,
            URI ocspResponder,
            boolean softFail,
            Duration reload,
            Duration sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
        this.prefix = prefix;
        this.chain = chain;
        this.key = key;
        this.ca = ca;
        this.crls = List.copyOf(crls);
        this.revocation = revocation;
        this.ocspResponder = ocspResponder;
        this.softFail = softFail;
        this.checkEveryMillis = reload.toMillis();
        if (revocation != Revocation.NONE && ca == null) {
            throw new ConfigException(prefix + "revocation: needs " + prefix + "ca, the CAs of client certificates");
        }
        if (revocation == Revocation.CRL && crls.isEmpty()) {
            throw new ConfigException(prefix + "revocation: crl needs " + prefix + "crl, the CRL files");
        }
        stamps = stamps();
        context = build();
        nextCheck = System.currentTimeMillis() + checkEveryMillis;
    }

    /**
     * The revocation and reload settings below {@code prefix} ({@code auth.eap.tls.}, {@code radsec.}): {@code crl},
     * {@code revocation}, {@code ocsp.url}, {@code ocsp.timeout}, {@code revocation.soft.fail}, {@code reload}.
     *
     * @param ca the client CAs file, empty when none
     */
    static TlsCredentials from(Config config, String prefix, Path chain, Path key, String ca) {
        return from(config, prefix, chain, key, ca, null);
    }

    /** @param sessionTimeout how long a TLS session may be resumed; {@code null}: the JDK's default */
    static TlsCredentials from(Config config, String prefix, Path chain, Path key, String ca, Duration sessionTimeout) {
        Revocation revocation = EapTlsConfig.choice(
                Revocation.class, prefix + "revocation", config.string(prefix + "revocation", "none"));
        String ocspUrl = config.string(prefix + "ocsp.url", "");
        if (revocation == Revocation.OCSP) {
            ocspTimeouts(config.duration(prefix + "ocsp.timeout", Duration.ofSeconds(2)));
        }
        return new TlsCredentials(
                prefix,
                chain,
                key,
                ca.isBlank() ? null : Path.of(ca),
                config.list(prefix + "crl", List.of()).stream()
                        .map(String::trim)
                        .filter(f -> !f.isEmpty())
                        .map(Path::of)
                        .toList(),
                revocation,
                ocspUrl.isBlank() ? null : URI.create(ocspUrl.trim()),
                config.bool(prefix + "revocation.soft.fail", false),
                config.duration(prefix + "reload", Duration.ofSeconds(60)),
                sessionTimeout);
    }

    /**
     * The JDK's OCSP client reads its timeouts from system properties, once: set them unless the operator did
     * ({@code -Dcom.sun.security.ocsp.timeout=...}).
     */
    private static void ocspTimeouts(Duration timeout) {
        String millis = timeout.toMillis() + "ms";
        if (System.getProperty("com.sun.security.ocsp.timeout") == null) {
            System.setProperty("com.sun.security.ocsp.timeout", millis);
        }
        if (System.getProperty("com.sun.security.ocsp.readtimeout") == null) {
            System.setProperty("com.sun.security.ocsp.readtimeout", millis);
        }
    }

    static final String STATELESS_TICKETS = "jdk.tls.server.enableSessionTicketExtension";

    /**
     * Keeps resumable TLS sessions in the server's cache instead of stateless tickets (ADR 0034): the JDK resumes a
     * stateless ticket without checking the session's age, the cache honours the session timeout, so a certificate
     * is checked again (revocation) at least that often. Must run before the first TLS class is loaded; the
     * operator's own setting wins.
     */
    static void statefulSessions() {
        if (System.getProperty(STATELESS_TICKETS) == null) {
            System.setProperty(STATELESS_TICKETS, "false");
        }
    }

    /** The current context; rebuilt first if the files changed since the last check. */
    SSLContext current() {
        if (checkEveryMillis > 0 && System.currentTimeMillis() >= nextCheck) {
            reloadIfChanged();
        }
        return context;
    }

    long reloads() {
        return reloads.get();
    }

    long reloadFailures() {
        return reloadFailures.get();
    }

    private synchronized void reloadIfChanged() {
        long now = System.currentTimeMillis();
        if (now < nextCheck) {
            return; // another worker just checked
        }
        nextCheck = now + checkEveryMillis;
        long[] current = stamps();
        if (Arrays.equals(current, stamps)) {
            return;
        }
        try {
            context = build();
            stamps = current;
            reloads.incrementAndGet();
            LOG.info("EAP TLS certificates reloaded from {}", chain);
        } catch (ConfigException e) {
            reloadFailures.incrementAndGet();
            LOG.warn("EAP TLS certificates changed but do not load, keeping the previous ones: {}", e.getMessage());
        }
    }

    /** Modification time and size of every file; -1 for a missing one. */
    private long[] stamps() {
        List<Path> files = new ArrayList<>(List.of(chain, key));
        if (ca != null) {
            files.add(ca);
        }
        files.addAll(crls);
        long[] s = new long[files.size() * 2];
        for (int i = 0; i < files.size(); i++) {
            try {
                s[2 * i] = Files.getLastModifiedTime(files.get(i)).toMillis();
                s[2 * i + 1] = Files.size(files.get(i));
            } catch (IOException e) {
                s[2 * i] = -1;
                s[2 * i + 1] = -1;
            }
        }
        return s;
    }

    private SSLContext build() {
        try {
            Certificate[] certificates = certificates(chain).toArray(Certificate[]::new);
            if (certificates.length == 0) {
                throw new ConfigException(prefix + "certificate: no certificate in " + chain);
            }
            PrivateKey privateKey = EapTlsConfig.privateKey(key, prefix + "key");
            if (!matches(privateKey, certificates[0])) {
                throw new ConfigException(prefix + "key: " + key + " is not the key of the certificate in " + chain);
            }
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry("server", privateKey, new char[0], certificates);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keys, new char[0]);
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(kmf.getKeyManagers(), ca == null ? null : trust().getTrustManagers(), null);
            if (sessionTimeout != null) {
                // the JDK reads 0 as "no limit": resumption off is a session that expires at once
                ssl.getServerSessionContext()
                        .setSessionTimeout((int) Math.max(1, Math.min(Integer.MAX_VALUE, sessionTimeout.toSeconds())));
            }
            return ssl;
        } catch (IOException | GeneralSecurityException e) {
            throw new ConfigException(prefix + "certificate: " + e.getMessage(), e);
        }
    }

    private TrustManagerFactory trust() throws IOException, GeneralSecurityException {
        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        int n = 0;
        for (Certificate c : certificates(ca)) {
            anchors.setCertificateEntry("ca-" + n++, c);
        }
        if (n == 0) {
            throw new ConfigException(prefix + "ca: no certificate in " + ca);
        }
        PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, new X509CertSelector());
        if (revocation == Revocation.NONE) {
            params.setRevocationEnabled(false);
        } else {
            List<CRL> lists = new ArrayList<>();
            for (Path file : crls) {
                try (InputStream in = Files.newInputStream(file)) {
                    lists.addAll(CertificateFactory.getInstance("X.509").generateCRLs(in));
                }
            }
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(lists)));
            PKIXRevocationChecker checker =
                    (PKIXRevocationChecker) CertPathBuilder.getInstance("PKIX").getRevocationChecker();
            EnumSet<PKIXRevocationChecker.Option> options = EnumSet.noneOf(PKIXRevocationChecker.Option.class);
            if (revocation == Revocation.CRL) {
                options.add(PKIXRevocationChecker.Option.PREFER_CRLS);
            }
            if (crls.isEmpty() || revocation == Revocation.CRL) {
                options.add(PKIXRevocationChecker.Option.NO_FALLBACK);
            }
            if (softFail) {
                options.add(PKIXRevocationChecker.Option.SOFT_FAIL);
            }
            checker.setOptions(options);
            if (ocspResponder != null) {
                checker.setOcspResponder(ocspResponder);
            }
            params.addCertPathChecker(checker);
            params.setRevocationEnabled(true);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(new CertPathTrustManagerParameters(params));
        return tmf;
    }

    /** Whether the key signs what the certificate's public key verifies. */
    private static boolean matches(PrivateKey privateKey, Certificate certificate) throws GeneralSecurityException {
        String algorithm = switch (privateKey.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> privateKey.getAlgorithm(); // Ed25519, Ed448
        };
        byte[] probe = "radiusward key check".getBytes(StandardCharsets.US_ASCII);
        Signature sign = Signature.getInstance(algorithm);
        sign.initSign(privateKey);
        sign.update(probe);
        byte[] signature = sign.sign();
        Signature verify = Signature.getInstance(algorithm);
        try {
            verify.initVerify(certificate.getPublicKey());
            verify.update(probe);
            return verify.verify(signature);
        } catch (GeneralSecurityException e) {
            return false; // a key of another algorithm
        }
    }

    static List<? extends Certificate> certificates(Path pem) throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(pem)) {
            return List.copyOf(CertificateFactory.getInstance("X.509").generateCertificates(in));
        }
    }
}
