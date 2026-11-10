/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.radius;

import io.radiusward.export.AccountingSink;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.SinkContext;
import io.radiusward.export.StorageMode;
import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Forwards the committed accounting of proxied realms to their home servers (ADR 0037): {@code sink.<name>.type =
 * radius}. The cluster has already committed and answered every event; this sink sends it on as an
 * Accounting-Request — its original attributes, Acct-Delay-Time raised by the time it spent with us, a new
 * Message-Authenticator for the home server's secret — and counts a batch written only when every request in it is
 * acknowledged. A home server that is down makes the exporter keep the batch and try again: nothing is lost, and the
 * NAS was never kept waiting.
 *
 * <p>Settings: {@code realms} (the realms to forward, {@code *} for every one), {@code servers} ({@code host[:port]},
 * tried in order), {@code secret}, {@code transport} ({@code udp} or {@code tls}: RadSec, with {@code tls.certificate},
 * {@code tls.key}, {@code tls.ca}, {@code tls.name}), {@code timeout}, {@code retries}, {@code strip}; {@code mode} must
 * be {@code sessions+events}. One exporter at a time forwards (the sink's lease); after a failover the last batch may
 * reach the home server again, as RADIUS accounting allows.
 */
public final class RadiusSink implements AccountingSink {

    static final int ACCOUNTING_REQUEST = 4;
    static final int ACCOUNTING_RESPONSE = 5;
    static final int USER_NAME = 1;
    static final int ACCT_DELAY_TIME = 41;
    static final int MESSAGE_AUTHENTICATOR = 80;
    private static final int WINDOW = 256;

    private List<String> realms;
    private List<InetSocketAddress> servers;
    private byte[] secret;
    private boolean tls;
    private SSLContext tlsContext;
    private String tlsName;
    private Duration timeout;
    private int retries;
    private boolean strip;
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final SecureRandom random = new SecureRandom();
    private DatagramSocket socket;
    private SSLSocket connection;
    private int connectedTo = -1;
    private long forwarded;

    @Override
    public void open(SinkContext context) throws Exception {
        if (context.mode() != StorageMode.SESSIONS_AND_EVENTS) {
            throw new IllegalArgumentException(
                    "sink." + context.name() + ".mode: sessions+events (the radius sink forwards events)");
        }
        realms = Arrays.stream(context.required("realms").split(","))
                .map(r -> r.trim().toLowerCase(Locale.ROOT))
                .filter(r -> !r.isEmpty())
                .toList();
        tls = switch (context.setting("transport", "udp").trim()) {
            case "udp" -> false;
            case "tls" -> true;
            default -> throw new IllegalArgumentException("sink." + context.name() + ".transport: udp or tls");
        };
        int defaultPort = tls ? 2083 : 1813;
        servers = new ArrayList<>();
        for (String s : context.required("servers").split(",")) {
            String server = s.trim();
            if (server.isEmpty()) {
                continue;
            }
            int colon = server.lastIndexOf(':');
            boolean port = colon > 0 && server.indexOf(':') == colon;
            servers.add(new InetSocketAddress(
                    InetAddress.getByName(port ? server.substring(0, colon) : server),
                    port ? Integer.parseInt(server.substring(colon + 1)) : defaultPort));
        }
        String secretText = context.setting("secret", tls ? "radsec" : "");
        if (secretText.isEmpty()) {
            throw new IllegalArgumentException("sink." + context.name() + ".secret is required over UDP");
        }
        secret = secretText.getBytes(StandardCharsets.UTF_8);
        timeout = duration(context.setting("timeout", "3s"));
        retries = Integer.parseInt(context.setting("retries", "2"));
        strip = Boolean.parseBoolean(context.setting("strip", "false"));
        if (tls) {
            tlsContext = context(
                    path(context.setting("tls.certificate", "")),
                    path(context.setting("tls.key", "")),
                    Path.of(context.required("tls.ca")));
            String name = context.setting("tls.name", "").trim();
            tlsName = name.isEmpty() ? null : name;
        } else {
            socket = new DatagramSocket();
        }
    }

    @Override
    public CheckpointStyle checkpointStyle() {
        return CheckpointStyle.IDEMPOTENT_REPLAY;
    }

    @Override
    public long storedPosition() {
        return -1; // the cluster's checkpoint for this sink is where forwarding resumes
    }

    @Override
    public void write(Batch batch) throws Exception {
        List<byte[]> requests = new ArrayList<>();
        for (ExportEvent e : batch.events()) {
            if (forwarded(e)) {
                requests.add(attributes(e));
            }
        }
        for (int from = 0; from < requests.size(); from += WINDOW) {
            List<byte[]> window = requests.subList(from, Math.min(requests.size(), from + WINDOW));
            IOException last = null;
            boolean done = false;
            for (int s = 0; s < servers.size() && !done; s++) {
                try {
                    done = tls ? sendTls(window, s) : sendUdp(window, servers.get(s));
                } catch (IOException ex) {
                    last = ex;
                    closeConnection();
                }
            }
            if (!done) {
                throw new IOException("no home server acknowledged the accounting", last);
            }
        }
        forwarded += requests.size();
    }

    long forwardedCount() {
        return forwarded;
    }

    /** Whether the event's User-Name has one of the forwarded realms. */
    boolean forwarded(ExportEvent e) {
        String user = attribute(e.rawAttributes(), USER_NAME);
        if (user == null) {
            return false;
        }
        int at = user.lastIndexOf('@');
        int slash = user.indexOf('\\');
        String realm = at >= 0 ? user.substring(at + 1) : slash > 0 ? user.substring(0, slash) : "";
        if (realm.isEmpty()) {
            return false;
        }
        return realms.contains("*") || realms.contains(realm.toLowerCase(Locale.ROOT));
    }

    /** The request's attributes: the original ones, Acct-Delay-Time raised, the realm stripped if configured. */
    byte[] attributes(ExportEvent e) {
        byte[] raw = e.rawAttributes();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        long delay = Math.max(0, (System.currentTimeMillis() - e.commitTime()) / 1000);
        for (int at = 0; at + 2 <= raw.length; ) {
            int type = raw[at] & 0xFF;
            int l = raw[at + 1] & 0xFF;
            if (l < 2 || at + l > raw.length) {
                break;
            }
            if (type == ACCT_DELAY_TIME && l == 6) {
                delay += ((raw[at + 2] & 0xFFL) << 24)
                        | ((raw[at + 3] & 0xFF) << 16)
                        | ((raw[at + 4] & 0xFF) << 8)
                        | (raw[at + 5] & 0xFF);
            } else if (type == USER_NAME && strip) {
                String user = new String(raw, at + 2, l - 2, StandardCharsets.UTF_8);
                int a = user.lastIndexOf('@');
                int s = user.indexOf('\\');
                String bare = a >= 0 ? user.substring(0, a) : s > 0 ? user.substring(s + 1) : user;
                byte[] b = bare.getBytes(StandardCharsets.UTF_8);
                out.write(USER_NAME);
                out.write(2 + b.length);
                out.writeBytes(b);
            } else if (type != MESSAGE_AUTHENTICATOR) {
                out.write(raw, at, l);
            }
            at += l;
        }
        long d = Math.min(delay, 0xFFFF_FFFFL);
        out.writeBytes(
                new byte[] {ACCT_DELAY_TIME, 6, (byte) (d >>> 24), (byte) (d >>> 16), (byte) (d >>> 8), (byte) d});
        return out.toByteArray();
    }

    /** An Accounting-Request with these attributes, identifier and a Message-Authenticator, signed. */
    private byte[] request(byte[] attributes, int identifier) {
        int length = RadiusPacket.HEADER_LENGTH + 18 + attributes.length;
        UnsafeBuffer p = new UnsafeBuffer(new byte[length]);
        p.putByte(0, (byte) ACCOUNTING_REQUEST);
        p.putByte(1, (byte) identifier);
        p.putShort(2, (short) length, ByteOrder.BIG_ENDIAN);
        p.putByte(20, (byte) MESSAGE_AUTHENTICATOR);
        p.putByte(21, (byte) 18);
        p.putBytes(38, attributes);
        authenticator.signAccountingRequest(p, 0, length, 20, secret);
        return p.byteArray();
    }

    /** Sends a window over UDP, resending what stays unanswered; whether every request was acknowledged. */
    private boolean sendUdp(List<byte[]> window, InetSocketAddress server) throws IOException {
        byte[][] packets = new byte[window.size()][];
        int base = random.nextInt(256);
        for (int i = 0; i < packets.length; i++) {
            packets[i] = request(window.get(i), (base + i) & 0xFF);
        }
        boolean[] acked = new boolean[packets.length];
        int open = packets.length;
        byte[] buffer = new byte[RadiusPacket.MAX_LENGTH];
        RadiusPacket response = new RadiusPacket();
        for (int attempt = 0; attempt <= retries && open > 0; attempt++) {
            for (int i = 0; i < packets.length; i++) {
                if (!acked[i]) {
                    socket.send(new DatagramPacket(packets[i], packets[i].length, server));
                }
            }
            long deadline = System.nanoTime() + timeout.toNanos();
            while (open > 0) {
                long left = (deadline - System.nanoTime()) / 1_000_000L;
                if (left <= 0) {
                    break;
                }
                socket.setSoTimeout((int) Math.max(1, left));
                DatagramPacket in = new DatagramPacket(buffer, buffer.length);
                try {
                    socket.receive(in);
                } catch (SocketTimeoutException e) {
                    break;
                }
                if (!in.getAddress().equals(server.getAddress())) {
                    continue;
                }
                int i = acknowledged(response, buffer, in.getLength(), packets, base);
                if (i >= 0 && !acked[i]) {
                    acked[i] = true;
                    open--;
                }
            }
        }
        return open == 0;
    }

    /** The index of the request a valid Accounting-Response answers, or -1. */
    private int acknowledged(RadiusPacket response, byte[] buffer, int length, byte[][] packets, int base) {
        if (response.wrap(new UnsafeBuffer(buffer), 0, length) != DecodeStatus.OK
                || response.code() != ACCOUNTING_RESPONSE) {
            return -1;
        }
        int i = (response.identifier() - base) & 0xFF;
        if (i >= packets.length) {
            return -1;
        }
        UnsafeBuffer request = new UnsafeBuffer(packets[i]);
        if (!authenticator.verifyResponse(response, request, 4, secret)
                || (response.hasMessageAuthenticator()
                        && !authenticator.verifyResponseMessageAuthenticator(response, request, 4, secret))) {
            return -1;
        }
        return i;
    }

    /** Sends a window over RadSec: written once (RFC 6613), every answer awaited; whether all were acknowledged. */
    private boolean sendTls(List<byte[]> window, int server) throws IOException {
        if (connection == null || connection.isClosed() || connectedTo != server) {
            closeConnection();
            connection = connect(servers.get(server));
            connectedTo = server;
        }
        byte[][] packets = new byte[window.size()][];
        int base = random.nextInt(256);
        OutputStream out = connection.getOutputStream();
        for (int i = 0; i < packets.length; i++) {
            packets[i] = request(window.get(i), (base + i) & 0xFF);
            out.write(packets[i]);
        }
        out.flush();
        boolean[] acked = new boolean[packets.length];
        int open = packets.length;
        connection.setSoTimeout((int) (timeout.toMillis() * (retries + 1)));
        DataInputStream in = new DataInputStream(connection.getInputStream());
        byte[] buffer = new byte[RadiusPacket.MAX_LENGTH];
        RadiusPacket response = new RadiusPacket();
        while (open > 0) {
            in.readFully(buffer, 0, 4);
            int length = ((buffer[2] & 0xFF) << 8) | (buffer[3] & 0xFF);
            if (length < RadiusPacket.HEADER_LENGTH || length > RadiusPacket.MAX_LENGTH) {
                throw new IOException("malformed packet from the home server");
            }
            in.readFully(buffer, 4, length - 4);
            int i = acknowledged(response, buffer, length, packets, base);
            if (i >= 0 && !acked[i]) {
                acked[i] = true;
                open--;
            }
        }
        return true;
    }

    private SSLSocket connect(InetSocketAddress server) throws IOException {
        SSLSocket s = (SSLSocket) tlsContext.getSocketFactory().createSocket();
        SSLParameters params = s.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        String name = tlsName != null ? tlsName : server.getHostString();
        if (!Character.isDigit(name.charAt(0)) && name.indexOf(':') < 0) {
            params.setServerNames(List.of(new javax.net.ssl.SNIHostName(name)));
        }
        s.setSSLParameters(params);
        s.connect(server, (int) timeout.toMillis()); // the certificate must carry the SNI name (tls.name)
        s.startHandshake();
        return s;
    }

    private void closeConnection() {
        if (connection != null) {
            try {
                connection.close();
            } catch (IOException e) {
                // closing anyway
            }
        }
        connection = null;
        connectedTo = -1;
    }

    static String attribute(byte[] raw, int type) {
        for (int at = 0; at + 2 <= raw.length; ) {
            int l = raw[at + 1] & 0xFF;
            if (l < 2 || at + l > raw.length) {
                return null;
            }
            if ((raw[at] & 0xFF) == type) {
                return new String(raw, at + 2, l - 2, StandardCharsets.UTF_8);
            }
            at += l;
        }
        return null;
    }

    /** {@code 500ms}, {@code 3s}, {@code 1m}. */
    static Duration duration(String text) {
        String t = text.trim().toLowerCase(Locale.ROOT);
        if (t.endsWith("ms")) {
            return Duration.ofMillis(Long.parseLong(t.substring(0, t.length() - 2)));
        }
        if (t.endsWith("s")) {
            return Duration.ofSeconds(Long.parseLong(t.substring(0, t.length() - 1)));
        }
        if (t.endsWith("m")) {
            return Duration.ofMinutes(Long.parseLong(t.substring(0, t.length() - 1)));
        }
        return Duration.ofSeconds(Long.parseLong(t));
    }

    private static Path path(String value) {
        return value.isBlank() ? null : Path.of(value.trim());
    }

    /** A TLS client context: our certificate and PKCS#8 key (PEM, optional) and the CAs the server must chain to. */
    static SSLContext context(Path certificate, Path key, Path ca) throws IOException, GeneralSecurityException {
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
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        int n = 0;
        for (Certificate c : certificates(ca)) {
            trust.setCertificateEntry("ca-" + n++, c);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    static List<? extends Certificate> certificates(Path pem) throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(pem)) {
            return List.copyOf(CertificateFactory.getInstance("X.509").generateCertificates(in));
        }
    }

    static PrivateKey privateKey(Path pem) throws IOException, GeneralSecurityException {
        String text = Files.readString(pem, StandardCharsets.US_ASCII);
        int begin = text.indexOf("-----BEGIN PRIVATE KEY-----");
        int end = text.indexOf("-----END PRIVATE KEY-----");
        if (begin < 0 || end < begin) {
            throw new IllegalArgumentException(pem + ": an unencrypted PKCS#8 key (BEGIN PRIVATE KEY) is needed");
        }
        byte[] der = Base64.getMimeDecoder().decode(text.substring(begin + 27, end));
        for (String algorithm : List.of("RSA", "EC", "Ed25519", "Ed448")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
            } catch (GeneralSecurityException e) {
                // not this algorithm
            }
        }
        throw new IllegalArgumentException(pem + ": no RSA, EC or EdDSA key");
    }

    @Override
    public void close() {
        closeConnection();
        if (socket != null) {
            socket.close();
        }
    }
}
