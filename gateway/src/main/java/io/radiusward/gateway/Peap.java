/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;

/**
 * PEAPv0 (MS-PEAP, ADR 0029, 0031, 0039): a TLS tunnel that authenticates only the server, then inside it the real identity
 * and an inner method from {@code auth.eap.peap.inner}: EAP-MSCHAPv2 (checked like MS-CHAPv2 outside: local NT hash,
 * cleartext opt-in, a credential verifier such as Netlogon), EAP-GTC (a password, checked like PAP) or EAP-TLS (a
 * client certificate); the peer may Nak to another listed one. Inner EAP messages go without their header (type and data only),
 * except the closing Result TLV, which carries it. Keys come from the tunnel (label {@code client EAP encryption},
 * TLS 1.3: RFC 9427).
 *
 * <p>Inner steps: Identity request → identity; MS-CHAPv2 Challenge → Response, checked; Success request → Success
 * response; Result TLV success → the peer's Result TLV → EAP-Success. A wrong credential: MS-CHAPv2 Failure request →
 * the peer's Failure response → Result TLV failure → EAP-Failure. With crypto-binding (ADR 0032) a Crypto-Binding TLV
 * goes with the successful Result TLV; a peer that checked it answers with its own, and the keys then come from the
 * compound session key.
 */
final class Peap extends TlsTunnel {

    static final int TYPE = 25;
    static final int MS_CHAP_V2 = 26;
    static final int TLV = 33;
    static final int GTC = 6;
    private static final byte[] GTC_PROMPT = "Password: ".getBytes(StandardCharsets.US_ASCII);
    private static final int OP_CHALLENGE = 1;
    private static final int OP_RESPONSE = 2;
    private static final int OP_SUCCESS = 3;
    private static final int OP_FAILURE = 4;
    private static final byte[] SERVER_NAME = "radiusward".getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Crypto-binding ({@code auth.eap.peap.crypto.binding}). */
    enum Binding {
        /** Not sent. */
        OFF,
        /** Sent; a peer may answer without one (it does not support it), but a wrong one fails. */
        OPTIONAL,
        /** Sent, and the peer must answer it. */
        REQUIRED
    }

    private enum State {
        HANDSHAKE,
        IDENTITY,
        CHALLENGE,
        SUCCESS,
        FAILURE,
        RESULT_OK,
        RESULT_FAILED
    }

    private State state = State.HANDSHAKE;
    private final byte[] authenticatorChallenge = new byte[16];
    private int msChapId;
    private int innerId;
    private String identity;
    private String authenticated;
    private MsChapV2 pendingExchange; // an inner check that could not be answered, for the retransmission
    private byte[] pendingPassword;
    private final java.util.List<Integer> innerTypes;
    private int innerType;
    private boolean innerBegun;
    private EapTls innerTls;
    private final Binding binding;
    private byte[] isk = new byte[32]; // the inner method's key; zeros for GTC
    private PeapCryptoBinding cryptoBinding;
    private final byte[] nonce = new byte[32];
    private byte[] sessionKey;
    private boolean fastReconnect;
    private final boolean requireClientCertificate;

    Peap(EapTlsConfig config) {
        this(config, java.util.List.of(MS_CHAP_V2), Binding.OPTIONAL);
    }

    /**
     * @param innerTypes the inner EAP types offered, first preferred
     * @param binding whether crypto-binding is sent and required
     */
    Peap(EapTlsConfig config, java.util.List<Integer> innerTypes, Binding binding) {
        this(config, innerTypes, binding, false);
    }

    /**
     * @param clientCertificate whether the outer TLS handshake requires a client certificate of {@code auth.eap.tls.ca}
     *     ({@code auth.eap.peap.client.certificate}), before and besides the inner method
     */
    Peap(EapTlsConfig config, java.util.List<Integer> innerTypes, Binding binding, boolean clientCertificate) {
        super(config);
        this.innerTypes = java.util.List.copyOf(innerTypes);
        this.binding = binding;
        this.requireClientCertificate = clientCertificate;
    }

    @Override
    public boolean innerOptional() {
        return innerType == EapTls.TYPE && !config.requireUser(); // a certificate inside: like EAP-TLS outside
    }

    @Override
    public int type() {
        return TYPE;
    }

    @Override
    boolean clientCertificate() {
        return requireClientCertificate;
    }

    /** PEAPv0 only (as other servers): a peer answering with version 1 fails at once; PEAPv1 is not planned. */
    @Override
    int version() {
        return 0;
    }

    @Override
    String keyLabel() {
        return "client EAP encryption";
    }

    @Override
    public String innerIdentity() {
        return authenticated;
    }

    @Override
    byte[] onFinished(boolean tls13) {
        if (!tls13) {
            return null; // TLS 1.2: the peer acknowledges our Finished first
        }
        state = State.IDENTITY;
        return new byte[] {EapPacket.TYPE_IDENTITY};
    }

    @Override
    Step onAck(Credentials credentials) {
        if (state == State.RESULT_OK && resumed()) {
            return Step.FAILED; // after a fast reconnect the peer must answer the Result TLV
        }
        if (state != State.HANDSHAKE) {
            return Step.FAILED;
        }
        state = State.IDENTITY;
        return sendApplication(new byte[] {EapPacket.TYPE_IDENTITY});
    }

    @Override
    Step onData(byte[] data, Credentials credentials) {
        if (data.length < 1) {
            return Step.FAILED;
        }
        return switch (state) {
            case IDENTITY -> identity(data);
            case CHALLENGE -> inner(data, credentials);
            case SUCCESS ->
                data.length >= 2 && (data[0] & 0xFF) == MS_CHAP_V2 && data[1] == OP_SUCCESS
                        ? result(true)
                        : Step.FAILED;
            case FAILURE -> result(false);
            case RESULT_OK -> {
                if (!resultAnswered(data)) {
                    yield Step.FAILED;
                }
                remember(authenticated);
                yield Step.succeeded(sessionKey);
            }
            default -> Step.FAILED;
        };
    }

    private Step identity(byte[] data) {
        if ((data[0] & 0xFF) != EapPacket.TYPE_IDENTITY || data.length < 2) {
            return Step.FAILED; // a Nak or anything else: only EAP-MSCHAPv2 is offered inside
        }
        identity = new String(data, 1, data.length - 1, StandardCharsets.UTF_8).trim();
        if (identity.isEmpty()) {
            return Step.FAILED;
        }
        return startInner(innerTypes.get(0));
    }

    /** Offers an inner method: its first request. */
    private Step startInner(int type) {
        innerType = type;
        innerBegun = false;
        state = State.CHALLENGE;
        if (type == GTC) {
            byte[] request = new byte[1 + GTC_PROMPT.length];
            request[0] = GTC;
            System.arraycopy(GTC_PROMPT, 0, request, 1, GTC_PROMPT.length);
            return sendApplication(request);
        }
        if (type == EapTls.TYPE) {
            innerTls = new EapTls(config, identity);
            Step first = innerTls.start(0, null);
            return first.done() ? Step.FAILED : sendApplication(prefixed(EapTls.TYPE, first.request()));
        }
        RANDOM.nextBytes(authenticatorChallenge);
        msChapId = RANDOM.nextInt(256);
        state = State.CHALLENGE;
        byte[] body = new byte[1 + 16 + SERVER_NAME.length];
        body[0] = 16;
        System.arraycopy(authenticatorChallenge, 0, body, 1, 16);
        System.arraycopy(SERVER_NAME, 0, body, 17, SERVER_NAME.length);
        return sendApplication(msChap(OP_CHALLENGE, body));
    }

    /** A response inside the tunnel to the offered inner method, or a Nak asking for another listed one. */
    private Step inner(byte[] data, Credentials credentials) {
        if (!innerBegun && (data[0] & 0xFF) == EapPacket.TYPE_NAK) {
            for (int i = 1; i < data.length; i++) {
                int wanted = data[i] & 0xFF;
                if (wanted != innerType && innerTypes.contains(wanted)) {
                    return startInner(wanted);
                }
            }
            return result(false); // nothing both sides support
        }
        if ((data[0] & 0xFF) != innerType) {
            return result(false);
        }
        innerBegun = true;
        return switch (innerType) {
            case GTC -> gtc(Arrays.copyOfRange(data, 1, data.length), credentials);
            case EapTls.TYPE -> innerTls(Arrays.copyOfRange(data, 1, data.length), credentials);
            default -> response(data, credentials);
        };
    }

    /** EAP-GTC: the response is the password (or a one-time password), checked like PAP. */
    private Step gtc(byte[] password, Credentials credentials) {
        if (credentials.inner() == null || password.length == 0) {
            return result(false);
        }
        Inner checked = credentials.inner().password(identity, password);
        if (checked.code() == AccessHandler.DROP) {
            pendingPassword = password;
            return Step.STORE_UNAVAILABLE;
        }
        pendingPassword = null;
        if (checked.code() != AccessHandler.ACCEPT) {
            return result(false);
        }
        authenticated = identity;
        return result(true);
    }

    /** EAP-TLS inside the tunnel: the inner handshake, header-less ([13] + EAP-TLS data). */
    private Step innerTls(byte[] data, Credentials credentials) {
        Step step = innerTls.process(0, data, credentials);
        if (!step.done()) {
            return sendApplication(prefixed(EapTls.TYPE, step.request()));
        }
        if (!step.success()) {
            return result(false);
        }
        // the inner certificate authenticated the inner identity, or names the user itself (identity = certificate)
        authenticated = innerTls.innerIdentity() != null ? innerTls.innerIdentity() : identity;
        isk = Arrays.copyOf(step.msk(), 32);
        return result(true);
    }

    private static byte[] prefixed(int type, byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) type;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }

    private Step response(byte[] data, Credentials credentials) {
        // type, opcode, id, ms-length(2), value-size 49, peer challenge 16, reserved 8, NT response 24, flags, name
        if (data.length < 5 + 1 + 49
                || (data[0] & 0xFF) != MS_CHAP_V2
                || data[1] != OP_RESPONSE
                || (data[5] & 0xFF) != 49) {
            return Step.FAILED;
        }
        byte[] peerChallenge = Arrays.copyOfRange(data, 6, 22);
        byte[] ntResponse = Arrays.copyOfRange(data, 30, 54);
        byte[] name = Arrays.copyOfRange(data, 55, data.length);
        byte[] challengeHash = MsChap.challengeHash(peerChallenge, authenticatorChallenge, MsChap.v2UserName(name));
        return check(
                new MsChapV2(challengeHash, ntResponse, authenticatorChallenge.clone(), peerChallenge, msChapId),
                credentials);
    }

    @Override
    Step onRetry(Credentials credentials) {
        if (pendingPassword != null) {
            return gtc(pendingPassword, credentials);
        }
        return pendingExchange == null ? Step.FAILED : check(pendingExchange, credentials);
    }

    /** The inner MS-CHAPv2 check by the gateway; its outcome as Success or Failure inside the tunnel. */
    private Step check(MsChapV2 exchange, Credentials credentials) {
        if (credentials.inner() == null) {
            return Step.FAILED;
        }
        Inner checked = credentials.inner().msChapV2(identity, exchange);
        if (checked.code() == AccessHandler.DROP) {
            pendingExchange = exchange;
            return Step.STORE_UNAVAILABLE;
        }
        pendingExchange = null;
        byte[] ntResponse = exchange.ntResponse();
        if (checked.code() != AccessHandler.ACCEPT || !checked.keyed()) {
            state = State.FAILURE;
            String failure = "E=691 R=0 C="
                    + HexFormat.of().formatHex(authenticatorChallenge).toUpperCase(Locale.ROOT)
                    + " V=3 M=Authentication failed";
            return sendApplication(msChap(OP_FAILURE, failure.getBytes(StandardCharsets.US_ASCII)));
        }
        authenticated = identity;
        isk = PeapCryptoBinding.msChapV2Isk(checked, ntResponse);
        state = State.SUCCESS;
        String success =
                checked.authenticatorResponse(ntResponse, exchange.challengeHash()) + " M=Authentication succeeded";
        return sendApplication(msChap(OP_SUCCESS, success.getBytes(StandardCharsets.US_ASCII)));
    }

    /**
     * Result TLV (MS-PEAP §2.2.8.1): with the EAP header, type 33, mandatory TLV 3, value 1 success / 2 failure; on
     * success also the Crypto-Binding TLV unless it is off.
     */
    private Step result(boolean success) {
        return sendApplication(resultTlv(success));
    }

    /**
     * Fast reconnect (ADR 0035): a resumed session whose first conversation authenticated an inner user skips the inner
     * method; the user is authorized again after success, like any inner user. Crypto-binding then binds the tunnel key alone.
     */
    @Override
    byte[] onResumed() {
        String user = remembered();
        if (user == null) {
            return null;
        }
        authenticated = user;
        fastReconnect = true;
        return resultTlv(true);
    }

    private byte[] resultTlv(boolean success) {
        state = success ? State.RESULT_OK : State.RESULT_FAILED;
        if (!success) {
            authenticated = null;
        }
        innerId = (innerId + 1) & 0xFF;
        byte[] bound = null;
        sessionKey = msk();
        if (success && binding != Binding.OFF) {
            RANDOM.nextBytes(nonce);
            nonce[31] &= (byte) 0xFE; // the last bit is the peer's (MS-PEAP)
            cryptoBinding = fastReconnect ? PeapCryptoBinding.fastReconnect(msk()) : new PeapCryptoBinding(msk(), isk);
            bound = cryptoBinding.request(nonce);
        }
        int length = 11 + (bound == null ? 0 : bound.length);
        byte[] p = new byte[length];
        p[0] = EapPacket.CODE_REQUEST;
        p[1] = (byte) innerId;
        p[2] = (byte) (length >>> 8);
        p[3] = (byte) length;
        p[4] = (byte) TLV;
        p[5] = (byte) 0x80;
        p[6] = 0x03;
        p[8] = 0x02;
        p[10] = (byte) (success ? 1 : 2);
        if (bound != null) {
            System.arraycopy(bound, 0, p, 11, bound.length);
        }
        return p;
    }

    /**
     * The peer's Result TLV, success, and its Crypto-Binding TLV checked: then the MSK comes from the compound session
     * key. Without one, the tunnel's MSK, unless binding is required.
     */
    private boolean resultAnswered(byte[] data) {
        EapPacket p = EapPacket.parse(data);
        if (p == null || p.code() != EapPacket.CODE_RESPONSE || p.type() != TLV) {
            return false;
        }
        byte[] tlvs = p.data();
        boolean resultOk = false;
        byte[] peerBinding = null;
        for (int at = 0; at + 4 <= tlvs.length; ) {
            int type = ((tlvs[at] & 0x3F) << 8) | (tlvs[at + 1] & 0xFF);
            int length = ((tlvs[at + 2] & 0xFF) << 8) | (tlvs[at + 3] & 0xFF);
            if (at + 4 + length > tlvs.length) {
                return false;
            }
            if (type == 3 && length == 2) {
                resultOk = tlvs[at + 4] == 0 && tlvs[at + 5] == 1;
            } else if (type == PeapCryptoBinding.TLV_TYPE) {
                peerBinding = Arrays.copyOfRange(tlvs, at, at + 4 + length);
            }
            at += 4 + length;
        }
        if (!resultOk) {
            return false;
        }
        if (cryptoBinding == null) {
            return true;
        }
        if (peerBinding == null) {
            return binding != Binding.REQUIRED;
        }
        if (!cryptoBinding.verifies(peerBinding, nonce)) {
            return false;
        }
        sessionKey = cryptoBinding.msk();
        return true;
    }

    /** An inner EAP-MSCHAPv2 message without the EAP header: type, opcode, id, MS-length, body. */
    private byte[] msChap(int opcode, byte[] body) {
        int msLength = 4 + body.length;
        byte[] m = new byte[1 + msLength];
        m[0] = (byte) MS_CHAP_V2;
        m[1] = (byte) opcode;
        m[2] = (byte) msChapId;
        m[3] = (byte) (msLength >>> 8);
        m[4] = (byte) msLength;
        System.arraycopy(body, 0, m, 5, body.length);
        return m;
    }
}
