/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.auth.Md4;
import io.radiusward.eap.EapPacket;
import io.radiusward.eap.MsChap;
import io.radiusward.eap.PeapCryptoBinding;
import io.radiusward.eap.TtlsAvp;
import io.radiusward.radius.codec.attributes.Ietf;
import io.radiusward.radius.codec.attributes.Microsoft;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;
import javax.net.ssl.SSLException;

/**
 * One EAP login as a device runs it through a NAS (RFC 3579): EAP-Response/Identity in an Access-Request, then each
 * Access-Challenge's EAP request answered in the next Access-Request with the server's State, until an Access-Accept
 * or Access-Reject. Requests of another method are answered with a Nak naming the login's method.
 */
final class EapSupplicant {

    private static final int MAX_ROUNDS = 64;
    private static final int TLV = 33; // PEAP's EAP-TLV inside the tunnel
    private static final SecureRandom RANDOM = new SecureRandom();

    private final RadiusClient client;
    private final byte[] secret;
    private final EapLogin login;
    private TlsPeer tls;
    private PeapInner peap;
    private TtlsInner ttls;

    EapSupplicant(RadiusClient client, byte[] secret, EapLogin login) {
        this.client = client;
        this.secret = secret;
        this.login = login;
    }

    EapResult run() {
        byte[] identity = login.identity().getBytes(StandardCharsets.UTF_8);
        EapPacket next = EapPacket.response(0, EapPacket.TYPE_IDENTITY, identity);
        byte[] state = null;
        for (int round = 1; round <= MAX_ROUNDS; round++) {
            byte[] authenticator = new byte[16];
            RANDOM.nextBytes(authenticator);
            PacketBuilder request =
                    client.accessRequest().authenticator(authenticator).attribute(Ietf.USER_NAME, login.identity());
            byte[] eap = next.encode();
            for (int at = 0; at < eap.length; at += 253) {
                request.attribute(Ietf.EAP_MESSAGE, Arrays.copyOfRange(eap, at, Math.min(eap.length, at + 253)));
            }
            if (state != null) {
                request.attribute(Ietf.STATE, state);
            }
            Optional<Response> answer = client.send(request.messageAuthenticator());
            if (answer.isEmpty()) {
                return result(EapResult.Outcome.NO_ANSWER, null, round, null);
            }
            Response response = answer.get();
            if (response.isAccept()) {
                return result(EapResult.Outcome.ACCEPTED, response, round, serverMsk(response, authenticator));
            }
            if (response.isReject()) {
                return result(EapResult.Outcome.REJECTED, response, round, null);
            }
            if (!response.isChallenge()) {
                return result(EapResult.Outcome.NO_ANSWER, response, round, null);
            }
            state = response.octets(Ietf.STATE).orElse(null);
            EapPacket challenge = EapPacket.parse(concat(response.all(Ietf.EAP_MESSAGE)));
            if (challenge == null || challenge.code() != EapPacket.CODE_REQUEST) {
                throw new IllegalStateException("the Access-Challenge carries no EAP request");
            }
            next = answer(challenge);
        }
        throw new IllegalStateException("no Access-Accept or Access-Reject after " + MAX_ROUNDS + " rounds");
    }

    private EapPacket answer(EapPacket request) {
        int id = request.identifier();
        int type = request.type();
        if (type == EapPacket.TYPE_IDENTITY) {
            return EapPacket.response(id, type, login.identity().getBytes(StandardCharsets.UTF_8));
        }
        if (type == EapPacket.TYPE_NOTIFICATION) {
            return EapPacket.response(id, type, new byte[0]);
        }
        int wanted = methodType();
        if (type != wanted) {
            return EapPacket.response(id, EapPacket.TYPE_NAK, new byte[] {(byte) wanted});
        }
        try {
            return EapPacket.response(
                    id,
                    type,
                    switch (login.method) {
                        case MD5 -> md5(id, request.data(), login.password);
                        case TLS, PEAP, TTLS -> tls().answer(request.data());
                    });
        } catch (SSLException e) {
            throw new IllegalStateException("TLS with the server failed: " + e.getMessage(), e);
        }
    }

    private int methodType() {
        return switch (login.method) {
            case MD5 -> EapPacket.TYPE_MD5;
            case TLS -> EapPacket.TYPE_TLS;
            case PEAP -> EapPacket.TYPE_PEAP;
            case TTLS -> EapPacket.TYPE_TTLS;
        };
    }

    private TlsPeer tls() {
        if (tls == null) {
            UnaryOperator<byte[]> tunnel = switch (login.method) {
                case PEAP -> peap = new PeapInner();
                case TTLS -> ttls = new TtlsInner();
                default -> null;
            };
            tls = new TlsPeer(login.sslContext(), login.tlsProtocol, login.fragmentSize, tunnel);
        }
        return tls;
    }

    /** EAP-MD5 (RFC 3748 §5.4): MD5 of the identifier, the password and the challenge. */
    static byte[] md5(int identifier, byte[] data, String password) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update((byte) identifier);
            md5.update(password.getBytes(StandardCharsets.UTF_8));
            md5.update(data, 1, data[0] & 0xFF);
            byte[] out = new byte[17];
            out[0] = 16;
            System.arraycopy(md5.digest(), 0, out, 1, 16);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("MD5 is part of every JDK", e);
        }
    }

    private EapResult result(EapResult.Outcome outcome, Response response, int rounds, byte[] serverMsk) {
        byte[] msk = null;
        if (outcome == EapResult.Outcome.ACCEPTED && tls != null && tls.established()) {
            try {
                msk = switch (login.method) {
                    case TLS -> tls.msk(EapPacket.TYPE_TLS, "client EAP encryption");
                    case PEAP ->
                        peap.boundMsk != null ? peap.boundMsk : tls.msk(EapPacket.TYPE_PEAP, "client EAP encryption");
                    case TTLS -> tls.msk(EapPacket.TYPE_TTLS, "ttls keying material");
                    default -> null;
                };
            } catch (SSLException e) {
                throw new IllegalStateException("cannot derive the MSK: " + e.getMessage(), e);
            }
        }
        boolean proved = peap != null ? peap.serverProved : ttls != null && ttls.serverProved;
        boolean bound = peap != null && peap.boundMsk != null;
        return new EapResult(outcome, response, rounds, msk, serverMsk, proved, bound);
    }

    /** MS-MPPE-Recv-Key and MS-MPPE-Send-Key of the Accept, decrypted (RFC 2548 §2.4): the MSK's two halves. */
    private byte[] serverMsk(Response accept, byte[] requestAuthenticator) {
        Optional<byte[]> recv = accept.vendor(Microsoft.VENDOR_ID, Microsoft.MPPE_RECV_KEY);
        Optional<byte[]> send = accept.vendor(Microsoft.VENDOR_ID, Microsoft.MPPE_SEND_KEY);
        if (recv.isEmpty() || send.isEmpty()) {
            return null;
        }
        byte[] r = MsChap.decryptKey(recv.get(), secret, requestAuthenticator);
        byte[] s = MsChap.decryptKey(send.get(), secret, requestAuthenticator);
        return r == null || s == null ? null : concat(List.of(r, s));
    }

    private static byte[] concat(List<byte[]> parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        parts.forEach(out::writeBytes);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        return concat(List.of(parts));
    }

    private static byte[] typed(int type, byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) type;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }

    /**
     * PEAPv0 inside the tunnel, as Windows behaves: the inner identity, EAP-MSCHAPv2 with the server's authenticator
     * response checked or EAP-GTC, a Nak for another method; then the Result TLV and, if the server sent one, the
     * Crypto-Binding TLV, checked and answered.
     */
    private final class PeapInner implements UnaryOperator<byte[]> {

        private byte[] challengeHash;
        private byte[] ntResponse;
        boolean serverProved;
        byte[] boundMsk;

        @Override
        public byte[] apply(byte[] in) {
            if (in.length == 0) {
                return null; // in PEAP the server speaks first inside the tunnel
            }
            EapPacket tlv = EapPacket.parse(in); // EAP-TLV is a whole EAP packet; the rest has no header
            if (tlv != null && tlv.code() == EapPacket.CODE_REQUEST && tlv.type() == TLV) {
                return result(tlv);
            }
            int type = in[0] & 0xFF;
            int wanted = login.inner == EapLogin.Inner.GTC ? EapPacket.TYPE_GTC : EapPacket.TYPE_MSCHAPV2;
            if (type == EapPacket.TYPE_IDENTITY) {
                return typed(type, login.user.getBytes(StandardCharsets.UTF_8));
            }
            if (type == EapPacket.TYPE_GTC && wanted == type) {
                return typed(type, login.password.getBytes(StandardCharsets.UTF_8));
            }
            if (type == EapPacket.TYPE_MSCHAPV2 && wanted == type) {
                return msChapV2(in);
            }
            return new byte[] {EapPacket.TYPE_NAK, (byte) wanted};
        }

        private byte[] msChapV2(byte[] in) {
            int op = in[1];
            int id = in[2] & 0xFF;
            if (op == 1) { // Challenge: value size, 16-byte challenge, server name
                byte[] authChallenge = Arrays.copyOfRange(in, 6, 22);
                byte[] peer = new byte[16];
                RANDOM.nextBytes(peer);
                byte[] name = login.user.getBytes(StandardCharsets.UTF_8);
                challengeHash = MsChap.challengeHash(peer, authChallenge, MsChap.v2UserName(name));
                ntResponse = MsChap.challengeResponse(challengeHash, MsChap.ntHash(login.password));
                int msLength = 4 + 1 + 49 + name.length;
                byte[] out = new byte[1 + msLength];
                out[0] = (byte) EapPacket.TYPE_MSCHAPV2;
                out[1] = 2;
                out[2] = (byte) id;
                out[3] = (byte) (msLength >>> 8);
                out[4] = (byte) msLength;
                out[5] = 49;
                System.arraycopy(peer, 0, out, 6, 16);
                System.arraycopy(ntResponse, 0, out, 30, 24);
                System.arraycopy(name, 0, out, 55, name.length);
                return out;
            }
            if (op == 3) { // Success: the server proves it knew the password before the device accepts it
                String text = new String(in, 5, in.length - 5, StandardCharsets.US_ASCII);
                serverProved = challengeHash != null
                        && text.startsWith(
                                MsChap.authenticatorResponse(MsChap.ntHash(login.password), ntResponse, challengeHash));
                if (!serverProved) {
                    throw new IllegalStateException("the server's MS-CHAPv2 authenticator response does not verify");
                }
                return new byte[] {(byte) EapPacket.TYPE_MSCHAPV2, 3};
            }
            return new byte[] {(byte) EapPacket.TYPE_MSCHAPV2, 4}; // Failure acknowledged
        }

        /** The Result TLV echoed, and the Crypto-Binding TLV answered if the server sent one. */
        private byte[] result(EapPacket request) {
            byte[] tlvs = request.data();
            int status = 2;
            byte[] binding = null;
            for (int at = 0; at + 4 <= tlvs.length; ) {
                int type = ((tlvs[at] & 0x3F) << 8) | (tlvs[at + 1] & 0xFF);
                int length = ((tlvs[at + 2] & 0xFF) << 8) | (tlvs[at + 3] & 0xFF);
                if (at + 4 + length > tlvs.length) {
                    break;
                }
                if (type == 3 && length == 2) {
                    status = tlvs[at + 5] & 0xFF;
                } else if (type == PeapCryptoBinding.TLV_TYPE) {
                    binding = Arrays.copyOfRange(tlvs, at, at + 4 + length);
                }
                at += 4 + length;
            }
            byte[] result = {(byte) 0x80, 3, 0, 2, 0, (byte) status};
            byte[] answer = new byte[0];
            if (binding != null && status == 1) {
                try {
                    byte[] isk = login.inner == EapLogin.Inner.MSCHAPV2 && ntResponse != null
                            ? PeapCryptoBinding.msChapV2Isk(Md4.digest(MsChap.ntHash(login.password)), ntResponse)
                            : new byte[32];
                    PeapCryptoBinding cb =
                            new PeapCryptoBinding(tls.msk(EapPacket.TYPE_PEAP, "client EAP encryption"), isk);
                    answer = cb.answer(binding);
                    if (answer == null) {
                        throw new IllegalStateException("the server's PEAP crypto-binding does not verify");
                    }
                    boundMsk = cb.msk();
                } catch (SSLException e) {
                    throw new IllegalStateException("cannot derive the tunnel key: " + e.getMessage(), e);
                }
            }
            return EapPacket.response(request.identifier(), TLV, concat(result, answer))
                    .encode();
        }
    }

    /**
     * EAP-TTLS inside the tunnel (RFC 5281): the user and its credential as AVPs: PAP, CHAP or MS-CHAP with the
     * tunnel's implicit challenge, or MS-CHAPv2 with the server's MS-CHAP2-Success checked.
     */
    private final class TtlsInner implements UnaryOperator<byte[]> {

        private byte[] challengeHash;
        private byte[] ntResponse;
        boolean serverProved;

        @Override
        public byte[] apply(byte[] in) {
            try {
                return in.length == 0 ? credentials() : success(in);
            } catch (SSLException e) {
                throw new IllegalStateException("cannot derive the implicit challenge: " + e.getMessage(), e);
            }
        }

        private byte[] credentials() throws SSLException {
            byte[] name = login.user.getBytes(StandardCharsets.UTF_8);
            byte[] password = login.password.getBytes(StandardCharsets.UTF_8);
            byte[] user = TtlsAvp.encode(Ietf.USER_NAME, 0, name);
            return switch (login.inner) {
                case PAP ->
                    concat(
                            user,
                            TtlsAvp.encode(
                                    Ietf.USER_PASSWORD, 0, Arrays.copyOf(password, (password.length + 15) / 16 * 16)));
                case CHAP -> {
                    byte[] implicit = tls.export("ttls challenge", 17);
                    byte[] challenge = Arrays.copyOf(implicit, 16);
                    yield concat(
                            user,
                            TtlsAvp.encode(Ietf.CHAP_CHALLENGE, 0, challenge),
                            TtlsAvp.encode(
                                    Ietf.CHAP_PASSWORD,
                                    0,
                                    Credentials.chapPassword(implicit[16] & 0xFF, password, challenge)));
                }
                case MSCHAP -> {
                    byte[] implicit = tls.export("ttls challenge", 9);
                    byte[] challenge = Arrays.copyOf(implicit, 8);
                    byte[] response =
                            new byte[50]; // ident, flags (1: the NT response counts), LM response, NT response
                    response[0] = implicit[8];
                    response[1] = 1;
                    System.arraycopy(
                            MsChap.challengeResponse(challenge, MsChap.ntHash(login.password)), 0, response, 26, 24);
                    yield concat(
                            user,
                            TtlsAvp.encode(Microsoft.CHAP_CHALLENGE, Microsoft.VENDOR_ID, challenge),
                            TtlsAvp.encode(Microsoft.CHAP_RESPONSE, Microsoft.VENDOR_ID, response));
                }
                case MSCHAPV2 -> {
                    byte[] implicit = tls.export("ttls challenge", 17);
                    byte[] challenge = Arrays.copyOf(implicit, 16);
                    byte[] peer = new byte[16];
                    RANDOM.nextBytes(peer);
                    challengeHash = MsChap.challengeHash(peer, challenge, MsChap.v2UserName(name));
                    ntResponse = MsChap.challengeResponse(challengeHash, MsChap.ntHash(login.password));
                    byte[] response = new byte[50];
                    response[0] = implicit[16];
                    System.arraycopy(peer, 0, response, 2, 16);
                    System.arraycopy(ntResponse, 0, response, 26, 24);
                    yield concat(
                            user,
                            TtlsAvp.encode(Microsoft.CHAP_CHALLENGE, Microsoft.VENDOR_ID, challenge),
                            TtlsAvp.encode(Microsoft.CHAP2_RESPONSE, Microsoft.VENDOR_ID, response));
                }
                case GTC -> throw new IllegalStateException("GTC is not a TTLS inner method");
            };
        }

        /** MS-CHAP2-Success: the server's authenticator response checked, then acknowledged with no data. */
        private byte[] success(byte[] in) {
            ByteBuffer b = ByteBuffer.wrap(in);
            int code = b.getInt(0);
            int length = b.getInt(4) & 0xFFFFFF;
            if (code == Microsoft.CHAP2_SUCCESS && length > 13 && challengeHash != null) {
                String text = new String(in, 13, length - 13, StandardCharsets.US_ASCII);
                serverProved = text.equals(
                        MsChap.authenticatorResponse(MsChap.ntHash(login.password), ntResponse, challengeHash));
                if (!serverProved) {
                    throw new IllegalStateException("the server's MS-CHAPv2 authenticator response does not verify");
                }
            }
            return new byte[0];
        }
    }
}
