/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLongArray;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The inner user of a tunnel checked by the home server of its realm (ADR 0044): the tunnel (PEAP, TTLS, TEAP) ends
 * here, its inner credential goes on as an Access-Request — PAP (User-Password), CHAP (CHAP-Password and
 * CHAP-Challenge) or MS-CHAPv2 (MS-CHAP-Challenge and MS-CHAP2-Response) — to the realm's UDP, TCP or RadSec home servers in pool
 * order, each tried {@code proxy.retries} more times after {@code proxy.timeout}. An Accept returns the home server's
 * MS-CHAP2-Success and MPPE keys for MS-CHAPv2 and its reply attributes, which our Accept carries; a Reject is a
 * reject; no answer at all leaves the request unanswered, so the NAS sends it again. Runs on the access workers, which
 * may wait.
 */
final class InnerProxy {

    private static final int MICROSOFT = 311;
    private static final int MS_CHAP_CHALLENGE = 11;
    private static final int MS_CHAP2_RESPONSE = 25;
    private static final int MS_CHAP2_SUCCESS = 26;
    private static final int MS_MPPE_SEND_KEY = 16;
    private static final int MS_MPPE_RECV_KEY = 17;
    private static final SecureRandom RANDOM = new SecureRandom();

    enum Counter {
        REQUESTS,
        ACCEPTED,
        REJECTED,
        NO_ANSWER
    }

    /**
     * A home server's verdict.
     *
     * @param reply its reply attributes for our Accept (without MPPE keys, MS-CHAP2-Success, Message-Authenticator,
     *     Proxy-State and State), empty unless accepted
     */
    record Result(EapMethod.Inner inner, byte[] reply) {}

    private final ProxyConfig config;
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);

    InnerProxy(ProxyConfig config) {
        this.config = config;
    }

    /** The realm of an inner user that goes to home servers; {@code null} if it is decided here. */
    ProxyConfig.Realm realm(String user) {
        byte[] name = user.getBytes(StandardCharsets.UTF_8);
        ProxyConfig.Realm realm = config.realmOf(new UnsafeBuffer(name), 0, name.length);
        return realm == null || realm.discover() ? null : realm;
    }

    Result password(String user, byte[] password) {
        ProxyConfig.Realm realm = realm(user);
        return send(
                realm,
                user,
                realm.strip(),
                (enc, auth, secret) -> enc.attribute(2, encryptPassword(password, auth, secret)));
    }

    Result chap(String user, int identifier, byte[] challenge, byte[] response) {
        ProxyConfig.Realm realm = realm(user);
        byte[] chapPassword = new byte[17];
        chapPassword[0] = (byte) identifier;
        System.arraycopy(response, 0, chapPassword, 1, 16);
        return send(
                realm,
                user,
                realm.strip(),
                (enc, auth, secret) -> enc.attribute(3, chapPassword).attribute(60, challenge));
    }

    /** MS-CHAPv2: the user name unstripped, since the peer's challenge hash covers it. */
    Result msChapV2(String user, EapMethod.MsChapV2 exchange) {
        byte[] response = new byte[50];
        response[0] = (byte) exchange.ident();
        System.arraycopy(exchange.peerChallenge(), 0, response, 2, 16);
        System.arraycopy(exchange.ntResponse(), 0, response, 26, 24);
        return send(
                realm(user),
                user,
                false,
                (enc, auth, secret) -> enc.vendorAttribute(
                                MICROSOFT, MS_CHAP_CHALLENGE, exchange.authenticatorChallenge())
                        .vendorAttribute(MICROSOFT, MS_CHAP2_RESPONSE, response));
    }

    private interface Credential {
        void write(RadiusPacketEncoder enc, byte[] authenticator, byte[] secret);
    }

    private Result send(ProxyConfig.Realm realm, String user, boolean strip, Credential credential) {
        increment(Counter.REQUESTS);
        ProxyConfig.Pool pool = config.pools().get(realm.pool());
        List<ProxyConfig.Home> homes = pool == null
                ? List.of()
                : pool.servers().stream()
                        .map(config.homes()::get)
                        .filter(h -> h != null && h.transport() != ProxyConfig.Transport.DTLS)
                        .toList();
        String name = strip ? stripped(user) : user;
        for (ProxyConfig.Home home : homes) {
            for (int attempt = 0; attempt <= config.retries(); attempt++) {
                Result r = exchange(home, name, credential);
                if (r != null) {
                    increment(r.inner().code() == AccessHandler.ACCEPT ? Counter.ACCEPTED : Counter.REJECTED);
                    return r;
                }
            }
        }
        increment(Counter.NO_ANSWER);
        return new Result(new EapMethod.Inner(AccessHandler.DROP, null), new byte[0]);
    }

    /** One request and its answer; {@code null} when none came in time. */
    private Result exchange(ProxyConfig.Home home, String name, Credential credential) {
        byte[] authenticator = new byte[16];
        RANDOM.nextBytes(authenticator);
        int id = RANDOM.nextInt(256);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, id)
                .authenticator(authenticator);
        int ma = enc.messageAuthenticator();
        enc.attribute(1, name);
        credential.write(enc, authenticator, home.secret());
        int length = enc.finish();
        RadiusAuthenticator signer = new RadiusAuthenticator();
        signer.signAccessRequest(buffer, 0, length, ma, home.secret());
        try {
            return home.transport() == ProxyConfig.Transport.UDP
                    ? overUdp(home, buffer, length, id, authenticator, signer)
                    : overStream(home, buffer, length, id, authenticator, signer);
        } catch (IOException e) {
            return null;
        }
    }

    private Result overUdp(
            ProxyConfig.Home home,
            UnsafeBuffer buffer,
            int length,
            int id,
            byte[] authenticator,
            RadiusAuthenticator signer)
            throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout((int) Math.max(1, config.timeout().toMillis()));
            socket.send(new DatagramPacket(buffer.byteArray(), length, home.address(), home.port()));
            byte[] in = new byte[RadiusPacket.MAX_LENGTH];
            long deadline = System.nanoTime() + config.timeout().toNanos();
            while (System.nanoTime() < deadline) {
                DatagramPacket p = new DatagramPacket(in, in.length);
                socket.receive(p);
                Result r = answer(home, buffer, in, p.getLength(), id, authenticator, signer);
                if (r != null) {
                    return r;
                }
            }
            return null;
        } catch (SocketTimeoutException e) {
            return null;
        }
    }

    /**
     * RadSec (TLS) or TCP (ADR 0055): a connection per request, closed after the answer; TLS sessions are resumed
     * from the context's cache.
     */
    private Result overStream(
            ProxyConfig.Home home,
            UnsafeBuffer buffer,
            int length,
            int id,
            byte[] authenticator,
            RadiusAuthenticator signer)
            throws IOException {
        int timeout = (int) Math.max(1, config.timeout().toMillis());
        try (java.net.Socket socket = connect(home, timeout)) {
            socket.setSoTimeout(timeout);
            java.io.OutputStream out = socket.getOutputStream();
            out.write(buffer.byteArray(), 0, length);
            out.flush();
            java.io.DataInputStream in = new java.io.DataInputStream(socket.getInputStream());
            byte[] packet = new byte[RadiusPacket.MAX_LENGTH];
            long deadline = System.nanoTime() + config.timeout().toNanos();
            while (System.nanoTime() < deadline) {
                in.readFully(packet, 0, 4);
                int n = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
                if (n < RadiusPacket.HEADER_LENGTH || n > RadiusPacket.MAX_LENGTH) {
                    return null; // the stream is out of step: give up on this server
                }
                in.readFully(packet, 4, n - 4);
                Result r = answer(home, buffer, packet, n, id, authenticator, signer);
                if (r != null) {
                    return r;
                }
            }
            return null;
        } catch (SocketTimeoutException | java.io.EOFException e) {
            return null;
        }
    }

    private final java.util.concurrent.ConcurrentHashMap<String, javax.net.ssl.SSLContext> contexts =
            new java.util.concurrent.ConcurrentHashMap<>();

    private java.net.Socket connect(ProxyConfig.Home home, int timeout) throws IOException {
        java.net.Socket plain = new java.net.Socket();
        plain.connect(new java.net.InetSocketAddress(home.address(), home.port()), timeout);
        if (home.transport() == ProxyConfig.Transport.TCP) {
            return plain;
        }
        javax.net.ssl.SSLContext context = contexts.computeIfAbsent(
                home.name(), n -> TlsClient.context(home.certificate(), home.key(), home.ca()));
        String serverName = home.serverName() != null ? home.serverName() : home.host();
        javax.net.ssl.SSLSocket tls =
                (javax.net.ssl.SSLSocket) context.getSocketFactory().createSocket(plain, serverName, home.port(), true);
        tls.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
        javax.net.ssl.SSLParameters params = tls.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS"); // the certificate must name serverName
        if (!serverName.isEmpty() && !Character.isDigit(serverName.charAt(0)) && serverName.indexOf(':') < 0) {
            params.setServerNames(List.of(new javax.net.ssl.SNIHostName(serverName)));
        }
        tls.setSSLParameters(params);
        tls.startHandshake();
        return tls;
    }

    /** The verdict in {@code in} if it answers this request; {@code null} if it is some other packet. */
    private Result answer(
            ProxyConfig.Home home,
            UnsafeBuffer buffer,
            byte[] in,
            int length,
            int id,
            byte[] authenticator,
            RadiusAuthenticator signer) {
        RadiusPacket answer = new RadiusPacket();
        if (answer.wrap(new UnsafeBuffer(in), 0, length) != DecodeStatus.OK
                || answer.identifier() != id
                || !signer.verifyResponse(answer, buffer, RadiusPacket.AUTHENTICATOR_OFFSET, home.secret())
                || (config.requireMessageAuthenticator() && !answer.hasMessageAuthenticator())
                || (answer.hasMessageAuthenticator()
                        && !signer.verifyResponseMessageAuthenticator(
                                answer, buffer, RadiusPacket.AUTHENTICATOR_OFFSET, home.secret()))) {
            return null; // not the answer to this request
        }
        if (answer.code() == RadiusCode.ACCESS_ACCEPT) {
            return accepted(Arrays.copyOf(in, length), answer, authenticator, home.secret());
        }
        return new Result(new EapMethod.Inner(AccessHandler.REJECT, null), new byte[0]); // a reject or a challenge
    }

    /** The Accept's MS-CHAP2-Success and MPPE keys, and the reply attributes to pass on. */
    private static Result accepted(byte[] packet, RadiusPacket answer, byte[] authenticator, byte[] secret) {
        String success = null;
        byte[] send = null;
        byte[] receive = null;
        ByteArrayOutputStream reply = new ByteArrayOutputStream();
        for (int at = answer.attributesOffset(); at < answer.attributesEnd(); ) {
            int type = packet[at] & 0xFF;
            int length = packet[at + 1] & 0xFF;
            boolean pass = type != 80 && type != 33 && type != 24 && type != 79;
            if (type == 26 && length >= 8) {
                int vendor = ((packet[at + 2] & 0xFF) << 24)
                        | ((packet[at + 3] & 0xFF) << 16)
                        | ((packet[at + 4] & 0xFF) << 8)
                        | (packet[at + 5] & 0xFF);
                int sub = packet[at + 6] & 0xFF;
                byte[] value = Arrays.copyOfRange(packet, at + 8, at + length);
                if (vendor == MICROSOFT && sub == MS_CHAP2_SUCCESS && value.length > 1) {
                    success = new String(value, 1, value.length - 1, StandardCharsets.US_ASCII);
                    pass = false;
                } else if (vendor == MICROSOFT && (sub == MS_MPPE_SEND_KEY || sub == MS_MPPE_RECV_KEY)) {
                    byte[] key = decryptKey(value, authenticator, secret);
                    if (sub == MS_MPPE_SEND_KEY) {
                        send = key;
                    } else {
                        receive = key;
                    }
                    pass = false;
                }
            }
            if (pass) {
                reply.write(packet, at, length);
            }
            at += length;
        }
        EapMethod.Inner inner = success != null
                ? EapMethod.Inner.proxied(success, send, receive)
                : new EapMethod.Inner(AccessHandler.ACCEPT, null);
        return new Result(inner, reply.toByteArray());
    }

    /** RFC 2865 §5.2: the password padded to 16-byte blocks, each XORed with MD5(secret + previous). */
    static byte[] encryptPassword(byte[] password, byte[] authenticator, byte[] secret) {
        int blocks = Math.max(1, (password.length + 15) / 16);
        byte[] out = Arrays.copyOf(password, blocks * 16);
        byte[] previous = authenticator;
        for (int b = 0; b < blocks; b++) {
            byte[] digest = md5(secret, previous);
            for (int i = 0; i < 16; i++) {
                out[b * 16 + i] ^= digest[i];
            }
            previous = Arrays.copyOfRange(out, b * 16, b * 16 + 16);
        }
        return out;
    }

    /** RFC 2548 §2.4.2: salt, then the encrypted length, key and padding; the 16-byte key, {@code null} if malformed. */
    static byte[] decryptKey(byte[] value, byte[] authenticator, byte[] secret) {
        if (value.length < 2 + 16 || (value.length - 2) % 16 != 0) {
            return null;
        }
        byte[] plain = new byte[value.length - 2];
        byte[] previous = null;
        for (int at = 0; at < plain.length; at += 16) {
            byte[] digest =
                    at == 0 ? md5(secret, authenticator, new byte[] {value[0], value[1]}) : md5(secret, previous);
            for (int i = 0; i < 16; i++) {
                plain[at + i] = (byte) (value[2 + at + i] ^ digest[i]);
            }
            previous = Arrays.copyOfRange(value, 2 + at, 2 + at + 16);
        }
        int length = plain[0] & 0xFF;
        return length < 16 || length > plain.length - 1 ? null : Arrays.copyOfRange(plain, 1, 17);
    }

    private static byte[] md5(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            for (byte[] part : parts) {
                md.update(part);
            }
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code user@realm} without the realm, {@code REALM}&#92;{@code user} without it either. */
    static String stripped(String user) {
        int at = user.lastIndexOf('@');
        if (at >= 0) {
            return user.substring(0, at);
        }
        int backslash = user.indexOf('\\');
        return backslash > 0 ? user.substring(backslash + 1) : user;
    }

    private void increment(Counter counter) {
        counts.incrementAndGet(counter.ordinal());
    }

    long get(Counter counter) {
        return counts.get(counter.ordinal());
    }

    void writeMetrics(io.radiusward.common.management.PrometheusWriter w, String gateway) {
        w.counter(
                "radiusward_gateway_inner_proxy_total",
                "Inner tunnel credentials checked by the home servers of their realms");
        for (Counter c : Counter.values()) {
            w.sample(get(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
        }
    }
}
