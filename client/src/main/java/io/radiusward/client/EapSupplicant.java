/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.eap.EapPacket;
import io.radiusward.eap.MsChap;
import io.radiusward.eap.TeapTlv;
import io.radiusward.radius.codec.attributes.Ietf;
import io.radiusward.radius.codec.attributes.Microsoft;
import java.nio.charset.StandardCharsets;
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
            EapBytes.RANDOM.nextBytes(authenticator);
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
            EapPacket challenge = EapPacket.parse(EapBytes.concat(response.all(Ietf.EAP_MESSAGE)));
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
                        case PWD -> (pwd == null ? pwd = new PwdPeer(login) : pwd).answer(request.data());
                        case SIM, AKA, AKA_PRIME ->
                            (sim == null ? sim = new SimPeer(login, methodType()) : sim).answer(id, request.data());
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
                case PEAP -> peap = new PeapInner(login, () -> tls);
                case TTLS -> ttls = new TtlsInner(login, () -> tls);
                case TEAP -> teap = new TeapInner(login, () -> tls);
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
        return r == null || s == null ? null : EapBytes.concat(List.of(r, s));
    }
}
