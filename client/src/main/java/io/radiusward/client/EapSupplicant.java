/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.auth.Md4;
import io.radiusward.eap.EapPacket;
import io.radiusward.eap.EapPwdKeys;
import io.radiusward.eap.Milenage;
import io.radiusward.eap.MsChap;
import io.radiusward.eap.P256;
import io.radiusward.eap.PeapCryptoBinding;
import io.radiusward.eap.SimKeys;
import io.radiusward.eap.SimMessage;
import io.radiusward.eap.TeapKeys;
import io.radiusward.eap.TeapTlv;
import io.radiusward.eap.TtlsAvp;
import io.radiusward.radius.codec.attributes.Ietf;
import io.radiusward.radius.codec.attributes.Microsoft;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
    private TeapInner teap;
    private PwdPeer pwd;
    private SimPeer sim;

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
                        case TLS, PEAP, TTLS, TEAP -> tls().answer(request.data());
                        case PWD -> (pwd == null ? pwd = new PwdPeer() : pwd).answer(request.data());
                        case SIM, AKA, AKA_PRIME ->
                            (sim == null ? sim = new SimPeer() : sim).answer(id, request.data());
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
            case TEAP -> EapPacket.TYPE_TEAP;
            case PWD -> EapPacket.TYPE_PWD;
            case SIM -> EapPacket.TYPE_SIM;
            case AKA -> EapPacket.TYPE_AKA;
            case AKA_PRIME -> EapPacket.TYPE_AKA_PRIME;
        };
    }

    private TlsPeer tls() {
        if (tls == null) {
            UnaryOperator<byte[]> tunnel = switch (login.method) {
                case PEAP -> peap = new PeapInner();
                case TTLS -> ttls = new TtlsInner();
                case TEAP -> teap = new TeapInner();
                default -> null;
            };
            int version = login.method == EapLogin.Method.TEAP ? TeapTlv.VERSION : 0;
            tls = new TlsPeer(login.sslContext(), login.tlsProtocol, login.fragmentSize, tunnel, version);
        }
        return tls;
    }

    /** EAP-MD5 (RFC 3748 §5.4): the value size, then CHAP's MD5 of the identifier, the password and the challenge. */
    static byte[] md5(int identifier, byte[] data, String password) {
        byte[] challenge = Arrays.copyOfRange(data, 1, 1 + (data[0] & 0xFF));
        byte[] chap = Credentials.chapPassword(identifier, password.getBytes(StandardCharsets.UTF_8), challenge);
        chap[0] = 16; // CHAP's identifier byte becomes EAP-MD5's value size
        return chap;
    }

    private EapResult result(EapResult.Outcome outcome, Response response, int rounds, byte[] serverMsk) {
        byte[] msk = null;
        if (outcome == EapResult.Outcome.ACCEPTED && sim != null) {
            msk = sim.msk;
        } else if (outcome == EapResult.Outcome.ACCEPTED && pwd != null) {
            msk = pwd.msk;
        } else if (outcome == EapResult.Outcome.ACCEPTED && teap != null) {
            msk = teap.msk;
        } else if (outcome == EapResult.Outcome.ACCEPTED && tls != null && tls.established()) {
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
        boolean proved = peap != null
                ? peap.serverProved
                : ttls != null ? ttls.serverProved : pwd != null ? pwd.serverProved : sim != null && sim.serverProved;
        boolean bound = peap != null ? peap.boundMsk != null : teap != null && teap.bindings > 0;
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
                case GTC, BASIC -> throw new IllegalStateException(login.inner + " is not a TTLS inner method");
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

    /**
     * TEAPv1 inside the tunnel (RFC 7170, RFC 9930): Basic-Password-Auth-Resp, or an inner EAP-GTC (a Nak to any other
     * inner method); each Crypto-Binding of the server checked and answered with the MSK Compound MAC, the keys chained
     * as the server does; the MSK from the last S-IMCK.
     */
    private final class TeapInner implements UnaryOperator<byte[]> {

        private TeapKeys keys;
        private byte[] simck;
        int bindings;
        byte[] msk;

        @Override
        public byte[] apply(byte[] in) {
            if (in.length == 0) {
                return null; // in TEAP the server speaks first inside the tunnel
            }
            try {
                return answer(in);
            } catch (SSLException e) {
                throw new IllegalStateException("cannot derive TEAP's keys: " + e.getMessage(), e);
            }
        }

        private byte[] answer(byte[] in) throws SSLException {
            byte[] binding = null;
            boolean resultAsked = false;
            boolean basicAsked = false;
            byte[] eap = null;
            int result = 0;
            for (int at = 0; at + 4 <= in.length; ) {
                int type = ((in[at] & 0xFF) << 8 | (in[at + 1] & 0xFF)) & 0x3FFF;
                int length = (in[at + 2] & 0xFF) << 8 | (in[at + 3] & 0xFF);
                byte[] value = Arrays.copyOfRange(in, at + 4, Math.min(in.length, at + 4 + length));
                switch (type) {
                    case TeapTlv.RESULT -> {
                        result = value.length > 1 ? value[1] : 0;
                        resultAsked = true;
                    }
                    case TeapTlv.CRYPTO_BINDING -> binding = Arrays.copyOfRange(in, at, at + 4 + length);
                    case TeapTlv.BASIC_PASSWORD_AUTH_REQ -> basicAsked = true;
                    case TeapTlv.EAP_PAYLOAD -> eap = value;
                    default -> {
                        // other TLVs (Identity-Type, Error) need no answer of their own here
                    }
                }
                at += 4 + length;
            }
            if (result == TeapTlv.FAILURE) {
                return TeapTlv.encode(TeapTlv.MANDATORY | TeapTlv.RESULT, new byte[] {0, TeapTlv.FAILURE});
            }
            if (binding != null) {
                return bind(binding, resultAsked);
            }
            if (basicAsked) {
                if (login.inner != EapLogin.Inner.BASIC) {
                    // Vendor-Id 0, then the NAK-Type: Basic-Password-Auth refused for an inner EAP method
                    return TeapTlv.encode(
                            TeapTlv.MANDATORY | TeapTlv.NAK,
                            new byte[] {0, 0, 0, 0, 0, TeapTlv.BASIC_PASSWORD_AUTH_REQ});
                }
                byte[] name = login.user.getBytes(StandardCharsets.UTF_8);
                byte[] pass = login.password.getBytes(StandardCharsets.UTF_8);
                return TeapTlv.encode(
                        TeapTlv.MANDATORY | TeapTlv.BASIC_PASSWORD_AUTH_RESP,
                        concat(new byte[] {(byte) name.length}, name, new byte[] {(byte) pass.length}, pass));
            }
            if (eap != null) {
                return TeapTlv.encode(TeapTlv.MANDATORY | TeapTlv.EAP_PAYLOAD, inner(EapPacket.parse(eap)));
            }
            throw new IllegalStateException("TEAP: nothing in the server's message to answer");
        }

        /** Identity, then EAP-GTC; a Nak naming GTC to any other method. */
        private byte[] inner(EapPacket request) {
            int type = request.type();
            byte[] data;
            if (type == EapPacket.TYPE_IDENTITY) {
                data = login.user.getBytes(StandardCharsets.UTF_8);
            } else if (type == EapPacket.TYPE_GTC) {
                data = login.password.getBytes(StandardCharsets.UTF_8);
            } else {
                type = EapPacket.TYPE_NAK;
                data = new byte[] {(byte) EapPacket.TYPE_GTC};
            }
            return EapPacket.response(request.identifier(), type, data).encode();
        }

        /** The server's Crypto-Binding checked, then answered with this round's keys (Basic and GTC have no MSK). */
        private byte[] bind(byte[] request, boolean resultAsked) throws SSLException {
            bindings++;
            if (simck == null) {
                simck = tls.export("EXPORTER: teap session key seed", TeapKeys.SIMCK_LENGTH);
                keys = new TeapKeys(tls.cipherSuite());
            }
            byte[] serverOuter = tls.serverOuterTlvs();
            byte[] peerOuter = new byte[0];
            TeapKeys.Compound compound = keys.next(simck, null, null);
            byte[] expected = keys.compoundMac(compound.cmk(), request, serverOuter, peerOuter);
            if (request.length != TeapTlv.BINDING_LENGTH
                    || !MessageDigest.isEqual(
                            expected, Arrays.copyOfRange(request, TeapTlv.MSK_MAC_AT, TeapTlv.BINDING_LENGTH))) {
                throw new IllegalStateException("the server's TEAP crypto-binding does not verify");
            }
            byte[] response = request.clone();
            response[7] = (byte) ((2 << 4) | 1); // MSK Compound MAC; Sub-Type 1: response
            response[8 + 31] |= 1; // the server's nonce with its last bit set
            byte[] mac = keys.compoundMac(compound.cmk(), response, serverOuter, peerOuter);
            System.arraycopy(mac, 0, response, TeapTlv.MSK_MAC_AT, mac.length);
            simck = compound.simck();
            msk = keys.msk(simck);
            byte[] intermediate =
                    TeapTlv.encode(TeapTlv.MANDATORY | TeapTlv.INTERMEDIATE_RESULT, new byte[] {0, TeapTlv.SUCCESS});
            byte[] result = resultAsked
                    ? TeapTlv.encode(TeapTlv.MANDATORY | TeapTlv.RESULT, new byte[] {0, TeapTlv.SUCCESS})
                    : new byte[0];
            return concat(intermediate, result, response);
        }
    }

    /**
     * EAP-pwd (RFC 5931), group 19: the ID exchange as the server offers it, the Commit with the password element, and
     * the Confirm, the server's checked before the peer's goes out; the MSK as both sides derive it.
     */
    private final class PwdPeer {

        private static final int ID = 1;
        private static final int COMMIT = 2;
        private static final int CONFIRM = 3;
        private static final int PREP_MS = 1;

        private byte[] serverId;
        private byte[] token;
        private byte[] preparedPassword;
        private BigInteger scalar;
        private P256.Point element;
        private BigInteger serverScalar;
        private P256.Point serverElement;
        private BigInteger k;
        boolean serverProved;
        byte[] msk;

        byte[] answer(byte[] request) {
            int exchange = request[0] & 0x3F;
            return switch (exchange) {
                case ID -> id(request);
                case COMMIT -> commit(request);
                case CONFIRM -> confirm(request);
                default -> throw new IllegalStateException("EAP-pwd: unknown exchange " + exchange);
            };
        }

        /** Group, random function, PRF, token and preparation as offered; then our identity. */
        private byte[] id(byte[] request) {
            int group = (request[1] & 0xFF) << 8 | (request[2] & 0xFF);
            if (group != 19) {
                throw new IllegalStateException("EAP-pwd: only group 19 is supported, the server offers " + group);
            }
            token = Arrays.copyOfRange(request, 5, 9);
            serverId = Arrays.copyOfRange(request, 10, request.length);
            preparedPassword = (request[9] & 0xFF) == PREP_MS
                    ? Md4.digest(MsChap.ntHash(login.password))
                    : login.password.getBytes(StandardCharsets.UTF_8);
            byte[] id = login.user.getBytes(StandardCharsets.UTF_8);
            byte[] d = new byte[1 + 9 + id.length];
            d[0] = ID;
            System.arraycopy(request, 1, d, 1, 9);
            System.arraycopy(id, 0, d, 10, id.length);
            return d;
        }

        private byte[] commit(byte[] request) {
            serverElement = P256.decode(request, 1);
            serverScalar = new BigInteger(1, Arrays.copyOfRange(request, 65, 97));
            P256.Point pwe = EapPwdKeys.passwordElement(
                    preparedPassword, serverId, login.user.getBytes(StandardCharsets.UTF_8), token);
            if (pwe == null || !P256.onCurve(serverElement)) {
                throw new IllegalStateException(
                        "EAP-pwd: no password element, or the server's element is off the curve");
            }
            BigInteger mask = P256.randomScalar(RANDOM);
            BigInteger privateValue = P256.randomScalar(RANDOM);
            scalar = privateValue.add(mask).mod(P256.N);
            element = P256.negate(P256.multiply(pwe, mask));
            k = P256.multiply(P256.add(P256.multiply(pwe, serverScalar), serverElement), privateValue)
                    .x();
            byte[] d = new byte[97];
            d[0] = COMMIT;
            System.arraycopy(element.encode(), 0, d, 1, 64);
            System.arraycopy(P256.bytes(scalar), 0, d, 65, 32);
            return d;
        }

        /** The server's Confirm proves it knew the password; only then our own goes out. */
        private byte[] confirm(byte[] request) {
            byte[] serverConfirm = Arrays.copyOfRange(request, 1, request.length);
            byte[] expected = EapPwdKeys.confirm(k, serverElement, serverScalar, element, scalar);
            serverProved = MessageDigest.isEqual(expected, serverConfirm);
            if (!serverProved) {
                throw new IllegalStateException("the server's EAP-pwd Confirm does not verify");
            }
            byte[] own = EapPwdKeys.confirm(k, element, scalar, serverElement, serverScalar);
            msk = EapPwdKeys.msk(k, own, serverConfirm, scalar, serverScalar);
            byte[] d = new byte[33];
            d[0] = CONFIRM;
            System.arraycopy(own, 0, d, 1, 32);
            return d;
        }
    }

    /**
     * EAP-SIM (RFC 4186), EAP-AKA (RFC 4187) and EAP-AKA′ (RFC 9048) with the login's {@link SimCard}: the permanent
     * identity, the card's MILENAGE answers and the keys of RFC 4186 §7, RFC 4187 §7 and RFC 9048 §3.3. The network is
     * checked as a device checks it (AUTN, then the server's AT_MAC); a network that fails is answered with
     * Authentication-Reject or Client-Error, an old sequence number with Synchronization-Failure.
     */
    private final class SimPeer {

        private static final int AKA_CHALLENGE = 1;
        private static final int AKA_AUTHENTICATION_REJECT = 2;
        private static final int AKA_SYNCHRONIZATION_FAILURE = 4;
        private static final int AKA_IDENTITY = 5;
        private static final int SIM_START = 10;
        private static final int SIM_CHALLENGE = 11;
        private static final int CLIENT_ERROR = 14;
        private static final int SIM_VERSION = 1;

        private final int type = methodType();
        private final byte[] identity = login.identity().getBytes(StandardCharsets.UTF_8);
        private byte[] nonceMt;
        private byte[] versionList;
        boolean serverProved;
        byte[] msk;

        byte[] answer(int identifier, byte[] request) {
            SimMessage m = SimMessage.parse(request);
            if (m == null) {
                return clientError();
            }
            int subtype = m.subtype();
            if (login.method == EapLogin.Method.SIM) {
                return switch (subtype) {
                    case SIM_START -> start(m);
                    case SIM_CHALLENGE -> simChallenge(identifier, request, m);
                    default -> clientError();
                };
            }
            return switch (subtype) {
                case AKA_IDENTITY ->
                    new SimMessage.Builder(AKA_IDENTITY)
                            .lengthPrefixed(SimMessage.AT_IDENTITY, identity)
                            .build();
                case AKA_CHALLENGE -> akaChallenge(identifier, request, m);
                default -> clientError();
            };
        }

        /** Version 1 selected, a fresh NONCE_MT, the permanent identity when the server asks for one. */
        private byte[] start(SimMessage m) {
            versionList = SimMessage.lengthPrefixed(m.get(SimMessage.AT_VERSION_LIST));
            if (versionList == null) {
                return clientError();
            }
            nonceMt = new byte[16];
            RANDOM.nextBytes(nonceMt);
            SimMessage.Builder b = new SimMessage.Builder(SIM_START)
                    .reserved(SimMessage.AT_NONCE_MT, nonceMt)
                    .uint16(SimMessage.AT_SELECTED_VERSION, SIM_VERSION);
            if (m.get(SimMessage.AT_PERMANENT_ID_REQ) != null
                    || m.get(SimMessage.AT_FULLAUTH_ID_REQ) != null
                    || m.get(SimMessage.AT_ANY_ID_REQ) != null) {
                b.lengthPrefixed(SimMessage.AT_IDENTITY, identity);
            }
            return b.build();
        }

        /** Three GSM triplets from the card; the server's MAC over NONCE_MT checked; our MAC over the SRESs. */
        private byte[] simChallenge(int identifier, byte[] request, SimMessage m) {
            byte[] rands = m.get(SimMessage.AT_RAND);
            if (nonceMt == null || rands == null || rands.length != 2 + 48) {
                return clientError();
            }
            Milenage milenage = login.card.milenage();
            byte[][] kc = new byte[3][];
            byte[] sres = new byte[12];
            for (int i = 0; i < 3; i++) {
                Milenage.Triplet t = milenage.gsm(Arrays.copyOfRange(rands, 2 + 16 * i, 18 + 16 * i));
                kc[i] = t.kc();
                System.arraycopy(t.sres(), 0, sres, 4 * i, 4);
            }
            milenage.erase();
            SimKeys.Keys keys = SimKeys.fullKeys(SimKeys.simMasterKey(identity, kc, nonceMt, versionList, SIM_VERSION));
            if (!serverMacValid(identifier, request, m, keys.kAut(), nonceMt)) {
                return clientError();
            }
            serverProved = true;
            msk = keys.msk();
            return signed(new SimMessage.Builder(SIM_CHALLENGE), identifier, keys.kAut(), sres);
        }

        /** AUTN checked by the card (MAC, then freshness), the server's MAC, then RES under our MAC. */
        private byte[] akaChallenge(int identifier, byte[] request, SimMessage m) {
            byte[] randAttribute = m.get(SimMessage.AT_RAND);
            byte[] autnAttribute = m.get(SimMessage.AT_AUTN);
            if (randAttribute == null
                    || randAttribute.length != 18
                    || autnAttribute == null
                    || autnAttribute.length != 18) {
                return clientError();
            }
            byte[] rand = Arrays.copyOfRange(randAttribute, 2, 18);
            byte[] autn = Arrays.copyOfRange(autnAttribute, 2, 18);
            Milenage milenage = login.card.milenage();
            try {
                Milenage.Quintet q = milenage.f2345(rand);
                byte[] sqn = new byte[6];
                for (int i = 0; i < 6; i++) {
                    sqn[i] = (byte) (autn[i] ^ q.ak()[i]);
                }
                byte[] mac = milenage.f1(rand, sqn, Arrays.copyOfRange(autn, 6, 8));
                if (!MessageDigest.isEqual(Arrays.copyOfRange(mac, 0, 8), Arrays.copyOfRange(autn, 8, 16))) {
                    return new SimMessage.Builder(AKA_AUTHENTICATION_REJECT).build(); // not our network
                }
                long received = 0;
                for (byte b : sqn) {
                    received = received << 8 | (b & 0xFF);
                }
                if (received <= login.card.sqn()) {
                    return synchronizationFailure(milenage, rand, q);
                }
                SimKeys.Keys keys;
                if (login.method == EapLogin.Method.AKA_PRIME) {
                    byte[] network = SimMessage.lengthPrefixed(m.get(SimMessage.AT_KDF_INPUT));
                    if (network == null || network.length == 0) {
                        return clientError();
                    }
                    byte[][] ckIk = SimKeys.akaPrimeCkIk(q.ck(), q.ik(), network, Arrays.copyOfRange(autn, 0, 6));
                    keys = SimKeys.akaPrimeKeys(ckIk[0], ckIk[1], identity);
                } else {
                    keys = SimKeys.fullKeys(SimKeys.akaMasterKey(identity, q.ik(), q.ck()));
                }
                if (!serverMacValid(identifier, request, m, keys.kAut(), null)) {
                    return clientError();
                }
                login.card.accepted(received);
                serverProved = true;
                msk = keys.msk();
                byte[] res = new byte[2 + q.res().length];
                res[1] = (byte) (q.res().length * 8);
                System.arraycopy(q.res(), 0, res, 2, q.res().length);
                return signed(
                        new SimMessage.Builder(AKA_CHALLENGE).add(SimMessage.AT_RES, res),
                        identifier,
                        keys.kAut(),
                        null);
            } finally {
                milenage.erase();
            }
        }

        /** AUTS: the card's SQN concealed with AK* and signed with MAC-S (f1*), so the network can resume from it. */
        private byte[] synchronizationFailure(Milenage milenage, byte[] rand, Milenage.Quintet q) {
            long ms = login.card.sqn();
            byte[] sqnMs = new byte[6];
            for (int i = 0; i < 6; i++) {
                sqnMs[i] = (byte) (ms >>> (40 - 8 * i));
            }
            byte[] auts = new byte[14];
            for (int i = 0; i < 6; i++) {
                auts[i] = (byte) (sqnMs[i] ^ q.akStar()[i]);
            }
            System.arraycopy(milenage.f1(rand, sqnMs, new byte[2]), 8, auts, 6, 8);
            return new SimMessage.Builder(AKA_SYNCHRONIZATION_FAILURE)
                    .add(SimMessage.AT_AUTS, auts)
                    .build();
        }

        private boolean serverMacValid(int identifier, byte[] request, SimMessage m, byte[] kAut, byte[] extra) {
            int at = m.macOffset();
            if (at < 0) {
                return false;
            }
            byte[] packet = SimMessage.packet(EapPacket.CODE_REQUEST, identifier, type, request, at);
            return MessageDigest.isEqual(mac(kAut, packet, extra), Arrays.copyOfRange(request, at, at + 16));
        }

        private byte[] signed(SimMessage.Builder b, int identifier, byte[] kAut, byte[] extra) {
            byte[] data = b.mac().build();
            byte[] packet = SimMessage.packet(EapPacket.CODE_RESPONSE, identifier, type, data, b.macOffset());
            System.arraycopy(mac(kAut, packet, extra), 0, data, b.macOffset(), 16);
            return data;
        }

        private byte[] mac(byte[] kAut, byte[] packet, byte[] extra) {
            return type == EapPacket.TYPE_AKA_PRIME
                    ? SimKeys.macSha256(kAut, packet, extra)
                    : SimKeys.macSha1(kAut, packet, extra);
        }

        /** Client-Error with code 0, "unable to process packet": the server ends the conversation. */
        private byte[] clientError() {
            return new SimMessage.Builder(CLIENT_ERROR)
                    .uint16(SimMessage.AT_CLIENT_ERROR_CODE, 0)
                    .build();
        }
    }
}
