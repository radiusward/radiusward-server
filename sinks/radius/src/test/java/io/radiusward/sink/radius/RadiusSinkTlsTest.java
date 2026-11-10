/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.radius;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.export.SinkContext;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.DataInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.agrona.concurrent.UnsafeBuffer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The radius sink over RadSec (RFC 6614, ADR 0037): a home server in the test that requires a client certificate,
 * checks the name it is reached by ({@code tls.name}) and acknowledges Accounting-Requests signed with the secret
 * {@code radsec}; failover from a server that refuses connections; configuration errors.
 */
class RadiusSinkTlsTest {

    static final byte[] RADSEC = "radsec".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private final List<AutoCloseable> closing = new ArrayList<>();

    @AfterEach
    void close() throws Exception {
        for (AutoCloseable c : closing) {
            c.close();
        }
    }

    /** A CA, a server certificate for {@code home.test} and a client certificate, all in PEM files. */
    record Pki(Path ca, Path serverCert, Path serverKey, Path clientCert, Path clientKey) {}

    private Pki pki() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair caKeys = generator.generateKeyPair();
        X509Certificate ca = certificate("CN=sink test CA", caKeys, caKeys, null, true);
        KeyPair serverKeys = generator.generateKeyPair();
        X509Certificate server = certificate("CN=home.test", serverKeys, caKeys, "home.test", false);
        KeyPair clientKeys = generator.generateKeyPair();
        X509Certificate client = certificate("CN=exporter", clientKeys, caKeys, null, false);
        return new Pki(
                pem(dir.resolve("ca.pem"), "CERTIFICATE", ca.getEncoded()),
                pem(dir.resolve("server.pem"), "CERTIFICATE", server.getEncoded()),
                pem(
                        dir.resolve("server.key"),
                        "PRIVATE KEY",
                        serverKeys.getPrivate().getEncoded()),
                pem(dir.resolve("client.pem"), "CERTIFICATE", client.getEncoded()),
                pem(
                        dir.resolve("client.key"),
                        "PRIVATE KEY",
                        clientKeys.getPrivate().getEncoded()));
    }

    private static X509Certificate certificate(String subject, KeyPair keys, KeyPair issuer, String dns, boolean ca)
            throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                ca ? new X500Name(subject) : new X500Name("CN=sink test CA"),
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(3600)),
                new X500Name(subject),
                keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (dns != null) {
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, dns)));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.getPrivate())));
    }

    private static Path pem(Path file, String type, byte[] der) throws Exception {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        return Files.writeString(file, "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n");
    }

    /** A RadSec home server: one connection at a time, acknowledges every valid Accounting-Request. */
    static final class FakeRadsecServer implements AutoCloseable {
        final SSLServerSocket server;
        final List<byte[]> received = new CopyOnWriteArrayList<>();

        FakeRadsecServer(Pki pki) throws Exception {
            PrivateKey key = RadiusSink.privateKey(pki.serverKey());
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry(
                    "server",
                    key,
                    new char[0],
                    RadiusSink.certificates(pki.serverCert()).toArray(java.security.cert.Certificate[]::new));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keys, new char[0]);
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            trust.setCertificateEntry("ca", RadiusSink.certificates(pki.ca()).get(0));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            server = (SSLServerSocket)
                    context.getServerSocketFactory().createServerSocket(0, 10, InetAddress.getLoopbackAddress());
            server.setNeedClientAuth(true);
            Thread t = new Thread(this::serve, "fake-radsec");
            t.setDaemon(true);
            t.start();
        }

        private void serve() {
            RadiusAuthenticator a = new RadiusAuthenticator();
            while (!server.isClosed()) {
                try (SSLSocket s = (SSLSocket) server.accept()) {
                    DataInputStream in = new DataInputStream(s.getInputStream());
                    OutputStream out = s.getOutputStream();
                    while (true) {
                        byte[] header = new byte[4];
                        in.readFully(header);
                        int length = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
                        byte[] request = new byte[length];
                        System.arraycopy(header, 0, request, 0, 4);
                        in.readFully(request, 4, length - 4);
                        RadiusPacket p = new RadiusPacket();
                        p.wrap(new UnsafeBuffer(request), 0, request.length);
                        if (!a.verifyAccountingRequest(p, RADSEC)) {
                            continue;
                        }
                        received.add(request);
                        UnsafeBuffer reply = new UnsafeBuffer(new byte[20]);
                        reply.putByte(0, (byte) 5);
                        reply.putByte(1, request[1]);
                        reply.putShort(2, (short) 20, ByteOrder.BIG_ENDIAN);
                        a.signResponse(reply, 0, 20, -1, new UnsafeBuffer(request), 4, RADSEC);
                        out.write(reply.byteArray(), 0, 20);
                        out.flush();
                    }
                } catch (Exception e) {
                    // connection ended: wait for the next
                }
            }
        }

        String address() {
            return "127.0.0.1:" + server.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            server.close();
        }
    }

    private RadiusSink sink(Map<String, String> settings) throws Exception {
        Map<String, String> s = new HashMap<>(Map.of("mode", "sessions+events", "realms", "partner.example"));
        s.putAll(settings);
        RadiusSink sink = new RadiusSink();
        sink.open(new SinkContext("home", 0, s, null));
        closing.add(sink);
        return sink;
    }

    @Test
    void forwardsOverRadsecWithAClientCertificateAndFailsOver() throws Exception {
        Pki pki = pki();
        FakeRadsecServer home = new FakeRadsecServer(pki);
        closing.add(home);
        int refused;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            refused = probe.getLocalPort(); // closed again: connections are refused
        }
        RadiusSink sink = sink(Map.of(
                "transport",
                "tls",
                "servers",
                "127.0.0.1:" + refused + "," + home.address(),
                "timeout",
                "2s",
                "retries",
                "0",
                "tls.certificate",
                pki.clientCert().toString(),
                "tls.key",
                pki.clientKey().toString(),
                "tls.ca",
                pki.ca().toString(),
                "tls.name",
                "home.test"));
        assertThat(sink.checkpointStyle())
                .isEqualTo(io.radiusward.export.AccountingSink.CheckpointStyle.IDEMPOTENT_REPLAY);

        sink.write(RadiusSinkTest.batch(
                RadiusSinkTest.event("alice@partner.example", "t-1", System.currentTimeMillis()),
                RadiusSinkTest.event("bob@other.org", "t-2", System.currentTimeMillis())));
        sink.write(RadiusSinkTest.batch( // the same connection again
                RadiusSinkTest.event("carol@partner.example", "t-3", System.currentTimeMillis())));
        assertThat(home.received).hasSize(2);
        assertThat(sink.forwardedCount()).isEqualTo(2);
        assertThat(new String(home.received.get(1), StandardCharsets.ISO_8859_1))
                .contains("carol@partner.example");
    }

    @Test
    void aServerNotNamedLikeItsCertificateIsNotTrusted() throws Exception {
        Pki pki = pki();
        FakeRadsecServer home = new FakeRadsecServer(pki);
        closing.add(home);
        RadiusSink sink = sink(Map.of(
                "transport",
                "tls",
                "servers",
                home.address(),
                "timeout",
                "1s",
                "retries",
                "0",
                "tls.certificate",
                pki.clientCert().toString(),
                "tls.key",
                pki.clientKey().toString(),
                "tls.ca",
                pki.ca().toString(),
                "tls.name",
                "elsewhere.test"));
        assertThatThrownBy(() -> sink.write(RadiusSinkTest.batch(
                        RadiusSinkTest.event("alice@partner.example", "t-4", System.currentTimeMillis()))))
                .hasMessageContaining("no home server acknowledged");
        assertThat(home.received).isEmpty();
    }

    @Test
    void configurationErrors() throws Exception {
        assertThatThrownBy(() -> sink(Map.of("transport", "sctp", "servers", "127.0.0.1", "secret", "s")))
                .hasMessageContaining("udp or tls");
        assertThatThrownBy(() -> sink(Map.of("servers", "127.0.0.1")))
                .hasMessageContaining("secret is required over UDP");
        Path plain = Files.writeString(
                dir.resolve("rsa.key"), "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n");
        assertThatThrownBy(() -> RadiusSink.privateKey(plain)).hasMessageContaining("BEGIN PRIVATE KEY");
        assertThat(RadiusSink.duration("2s")).isEqualTo(Duration.ofSeconds(2));
        assertThat(RadiusSink.duration("1m")).isEqualTo(Duration.ofMinutes(1));
        assertThat(RadiusSink.duration("3")).isEqualTo(Duration.ofSeconds(3));
        RadiusSink sink = sink(Map.of("servers", " 127.0.0.1 , ,", "secret", "s"));
        assertThat(sink.storedPosition())
                .as("resumes from the cluster's checkpoint")
                .isEqualTo(-1);
    }
}
