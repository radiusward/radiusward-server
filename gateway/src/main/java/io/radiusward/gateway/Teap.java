/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLException;

/**
 * TEAPv1 (RFC 7170 with RFC 9930; ADR 0041): a TLS tunnel that authenticates the server, then inside it TLVs. The
 * Start carries an Authority-ID Outer TLV. Phase 2 asks for the inner identity in an EAP-Payload TLV and runs an inner
 * EAP method ({@link InnerEap}: EAP-MSCHAPv2, EAP-GTC, EAP-MD5 from {@code auth.eap.teap.inner}), or asks for a
 * Basic-Password-Auth-Resp when {@code basic} is listed first; a NAK TLV for Basic-Password-Auth falls back to the
 * listed EAP methods. After the inner method the server sends Intermediate-Result, Result and a Crypto-Binding TLV
 * whose Compound MAC binds the inner method's keys to the tunnel ({@link TeapKeys}); the peer must answer with a
 * matching Crypto-Binding and a successful Result, and the MSK then comes from the last S-IMCK. With
 * {@code auth.eap.teap.identity} (e.g. {@code machine, user}) the server asks for each identity type in turn
 * (Identity-Type TLV, §4.2.3) and chains the inner methods: each one's keys extend the previous S-IMCK, the Result
 * comes with the last binding, and the user (else the machine) is the authenticated identity. A failure sends a
 * failed Result first. A resumed TLS session still runs the inner method: wpa_supplicant's TEAP peer does not offer
 * resumption, so a shortcut could not be tested against it.
 */
final class Teap extends TlsTunnel {

    static final int TYPE = 55;
    static final int TEAP_VERSION = 1;

    static final int TLV_AUTHORITY_ID = 1;
    static final int TLV_IDENTITY_TYPE = 2;
    static final int TLV_RESULT = 3;
    static final int TLV_NAK = 4;
    static final int TLV_ERROR = 5;
    static final int TLV_EAP_PAYLOAD = 9;
    static final int TLV_INTERMEDIATE_RESULT = 10;
    static final int TLV_CRYPTO_BINDING = 12;
    static final int TLV_BASIC_PASSWORD_AUTH_REQ = 13;
    static final int TLV_BASIC_PASSWORD_AUTH_RESP = 14;
    static final int MANDATORY = 0x8000;
    static final int SUCCESS = 1;
    static final int FAILURE = 2;
    static final int BASIC = -1; // in the inner list: Basic-Password-Auth instead of an EAP type
    static final int IDENTITY_USER = 1;
    static final int IDENTITY_MACHINE = 2;
    private static final int BINDING_LENGTH = 4 + 4 + 32 + 20 + 20;
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum State {
        HANDSHAKE,
        BASIC_AUTH,
        INNER_EAP,
        BINDING,
        FAILED
    }

    private final List<Integer> inner;
    private final byte[] authorityId;
    private final List<Integer> identityTypes; // empty: any identity, one inner method
    private int round; // index in identityTypes
    private String userIdentity;
    private String machineIdentity;
    private State state = State.HANDSHAKE;
    private byte[] serverOuterTlvs = new byte[0];
    private byte[] peerOuterTlvs = new byte[0];
    private boolean peerOuterSeen;
    private TeapKeys keys;
    private byte[] simck;
    private TeapKeys.Compound compound;
    private final byte[] nonce = new byte[32];
    private InnerEap innerEap;
    private String user;
    private String authenticated;
    private byte[] pendingBasic;
    private byte[] pendingBasicUser;

    /**
     * @param inner the inner methods offered, first preferred: EAP types of {@link InnerEap}, and {@link #BASIC}
     * @param authorityId the server's Authority-ID (RFC 7170 §4.2.2)
     */
    Teap(EapTlsConfig config, List<Integer> inner, byte[] authorityId) {
        this(config, inner, authorityId, List.of());
    }

    /** @param identityTypes the identity types asked for in turn ({@link #IDENTITY_USER}, {@link #IDENTITY_MACHINE}); empty: any */
    Teap(EapTlsConfig config, List<Integer> inner, byte[] authorityId, List<Integer> identityTypes) {
        super(config);
        this.inner = List.copyOf(inner);
        this.authorityId = authorityId.clone();
        this.identityTypes = List.copyOf(identityTypes);
    }

    private boolean lastRound() {
        return round >= identityTypes.size() - 1;
    }

    /** The Identity-Type TLV of this round, none without identity types. */
    private byte[] identityType() {
        return identityTypes.isEmpty()
                ? new byte[0]
                : tlv(MANDATORY | TLV_IDENTITY_TYPE, new byte[] {0, (byte) (int) identityTypes.get(round)});
    }

    @Override
    public int type() {
        return TYPE;
    }

    @Override
    boolean clientCertificate() {
        return false;
    }

    @Override
    int version() {
        return TEAP_VERSION;
    }

    @Override
    String keyLabel() {
        return "client EAP encryption"; // unused: the MSK comes from S-IMCK
    }

    @Override
    public String innerIdentity() {
        return authenticated;
    }

    /** S, O and version 1; the Outer TLV Length; the Authority-ID TLV (§4.1, §4.2.2). */
    @Override
    byte[] startMessage() {
        serverOuterTlvs = tlv(TLV_AUTHORITY_ID, authorityId);
        byte[] start = new byte[1 + 4 + serverOuterTlvs.length];
        start[0] = (byte) (FLAG_START | FLAG_OUTER_TLVS | TEAP_VERSION);
        int n = serverOuterTlvs.length;
        start[1] = (byte) (n >>> 24);
        start[2] = (byte) (n >>> 16);
        start[3] = (byte) (n >>> 8);
        start[4] = (byte) n;
        System.arraycopy(serverOuterTlvs, 0, start, 5, n);
        return start;
    }

    @Override
    void onOuterTlvs(byte[] tlvs) {
        if (!peerOuterSeen) {
            peerOuterTlvs = tlvs; // only those of the peer's first message count for the Compound MAC
        }
        peerOuterSeen = true;
    }

    @Override
    byte[] onFinished(boolean tls13) {
        if (!seed()) {
            return null;
        }
        return beginInner(inner.get(0));
    }

    @Override
    Step onAck(Credentials credentials) {
        return Step.FAILED; // the peer always answers with TLVs
    }

    /** S-IMCK[0] from the tunnel; the key hierarchy follows the negotiated suite. */
    private boolean seed() {
        try {
            simck = export("EXPORTER: teap session key seed", TeapKeys.SIMCK_LENGTH);
        } catch (SSLException e) {
            return false;
        }
        keys = new TeapKeys(cipherSuite());
        return true;
    }

    private byte[] beginInner(int method) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (method == BASIC) {
            state = State.BASIC_AUTH;
            out.writeBytes(tlv(MANDATORY | TLV_BASIC_PASSWORD_AUTH_REQ, new byte[0]));
        } else {
            state = State.INNER_EAP;
            innerEap = new InnerEap(inner.stream().filter(t -> t != BASIC).toList(), config);
            out.writeBytes(tlv(MANDATORY | TLV_EAP_PAYLOAD, innerEap.requestIdentity()));
        }
        out.writeBytes(identityType());
        return out.toByteArray();
    }

    @Override
    Step onData(byte[] data, Credentials credentials) {
        Tlvs t = Tlvs.parse(data);
        if (t == null || t.result == FAILURE || state == State.FAILED) {
            return Step.FAILED;
        }
        return switch (state) {
            case BASIC_AUTH -> {
                if (t.nak && inner.stream().anyMatch(m -> m != BASIC)) {
                    yield sendApplication(beginInner(
                            inner.stream().filter(m -> m != BASIC).findFirst().orElseThrow()));
                }
                if (t.basicAuth == null) {
                    yield Step.FAILED;
                }
                yield basicAuth(t.basicAuth, credentials);
            }
            case INNER_EAP -> {
                if (t.eapPayload == null || credentials.inner() == null) {
                    yield Step.FAILED;
                }
                yield afterInner(innerEap.handle(t.eapPayload, credentials));
            }
            case BINDING -> bound(t, credentials);
            default -> Step.FAILED;
        };
    }

    @Override
    Step onRetry(Credentials credentials) {
        if (state == State.BASIC_AUTH && pendingBasic != null) {
            return checkBasic(pendingBasicUser, pendingBasic, credentials);
        }
        if (state == State.INNER_EAP && innerEap != null) {
            return afterInner(innerEap.retry(credentials));
        }
        return Step.FAILED;
    }

    /** Basic-Password-Auth-Resp (§4.2.15): Userlen, Username, Passlen, Password; checked like PAP. */
    private Step basicAuth(byte[] value, Credentials credentials) {
        if (value.length < 1) {
            return failure();
        }
        int userLength = value[0] & 0xFF;
        if (value.length < 2 + userLength) {
            return failure();
        }
        int passLength = value[1 + userLength] & 0xFF;
        if (value.length != 2 + userLength + passLength || credentials.inner() == null) {
            return failure();
        }
        byte[] name = Arrays.copyOfRange(value, 1, 1 + userLength);
        byte[] password = Arrays.copyOfRange(value, 2 + userLength, value.length);
        return checkBasic(name, password, credentials);
    }

    private Step checkBasic(byte[] name, byte[] password, Credentials credentials) {
        user = new String(name, StandardCharsets.UTF_8);
        EapMethod.Inner checked = credentials.inner().password(user, password);
        if (checked.code() == AccessHandler.DROP) {
            pendingBasicUser = name;
            pendingBasic = password;
            return Step.STORE_UNAVAILABLE;
        }
        pendingBasic = null;
        if (checked.code() != AccessHandler.ACCEPT) {
            return failure();
        }
        identified(user);
        return sendApplication(bind(null, null)); // no inner key
    }

    /** The identity this round authenticated, by its type. */
    private void identified(String name) {
        if (!identityTypes.isEmpty() && identityTypes.get(round) == IDENTITY_MACHINE) {
            machineIdentity = name;
        } else {
            userIdentity = name;
        }
    }

    private Step afterInner(Step step) {
        if (step.unavailable()) {
            return Step.STORE_UNAVAILABLE;
        }
        if (!step.done()) {
            return sendApplication(tlv(MANDATORY | TLV_EAP_PAYLOAD, step.request()));
        }
        if (!step.success()) {
            return failure();
        }
        user = innerEap.identity();
        identified(user);
        return sendApplication(bind(innerEap.msk(), null));
    }

    /** Intermediate-Result, Result and the Crypto-Binding request for the inner method's keys (§4.2.13, §5.3). */
    private byte[] bind(byte[] msk, byte[] emsk) {
        compound = keys.next(simck, msk, emsk);
        RANDOM.nextBytes(nonce);
        nonce[31] &= (byte) 0xFE; // a request's nonce ends with a 0 bit
        byte[] binding = new byte[BINDING_LENGTH];
        binding[0] = (byte) ((MANDATORY | TLV_CRYPTO_BINDING) >>> 8);
        binding[1] = (byte) TLV_CRYPTO_BINDING;
        binding[3] = (byte) (BINDING_LENGTH - 4);
        binding[5] = TEAP_VERSION; // Version
        binding[6] = TEAP_VERSION; // Received-Ver: the peer's, which is 1
        binding[7] = (byte) (2 << 4); // Flags: MSK Compound MAC; Sub-Type 0: request
        System.arraycopy(nonce, 0, binding, 8, 32);
        byte[] mac = keys.compoundMac(compound.cmk(), binding, serverOuterTlvs, peerOuterTlvs);
        System.arraycopy(mac, 0, binding, 4 + 4 + 32 + 20, 20);
        state = State.BINDING;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(result(TLV_INTERMEDIATE_RESULT, SUCCESS));
        if (lastRound()) {
            out.writeBytes(result(TLV_RESULT, SUCCESS)); // the final Result comes with the last binding (§3.6)
        }
        out.writeBytes(binding);
        return out.toByteArray();
    }

    /**
     * The peer's answer to the binding: a Crypto-Binding response with its MSK Compound MAC, an Intermediate-Result
     * success, and on the last round a Result success; then the next identity type, or the end.
     */
    private Step bound(Tlvs t, Credentials credentials) {
        byte[] b = t.binding;
        boolean last = lastRound();
        if (b == null
                || (last && t.result != SUCCESS)
                || t.intermediate == FAILURE
                || (!last && t.intermediate != SUCCESS)
                || b.length != BINDING_LENGTH) {
            return Step.FAILED;
        }
        int flags = (b[7] & 0xFF) >>> 4;
        boolean nonceAnswered = Arrays.equals(Arrays.copyOf(b, 8 + 31), concat(Arrays.copyOf(b, 8), nonce, 31))
                && (b[8 + 31] & 0xFF) == ((nonce[31] & 0xFF) | 1);
        if (b[5] != TEAP_VERSION
                || b[6] != TEAP_VERSION
                || (b[7] & 0x0F) != 1 // Sub-Type: response
                || (flags != 2 && flags != 3) // the peer has no EMSK of ours to bind: the MSK Compound MAC
                || !nonceAnswered) {
            return Step.FAILED;
        }
        byte[] expected = keys.compoundMac(compound.cmk(), b, serverOuterTlvs, peerOuterTlvs);
        if (!MessageDigest.isEqual(expected, Arrays.copyOfRange(b, 4 + 4 + 32 + 20, BINDING_LENGTH))) {
            return Step.FAILED;
        }
        simck = compound.simck();
        if (!last) {
            round++;
            return sendApplication(beginInner(inner.get(0))); // the next identity type, chained on this S-IMCK
        }
        authenticated = userIdentity != null ? userIdentity : machineIdentity;
        remember(authenticated);
        return Step.succeeded(keys.msk(simck));
    }

    /** A failed Result; the peer's answer then ends the conversation with EAP-Failure. */
    private Step failure() {
        state = State.FAILED;
        return sendApplication(result(TLV_RESULT, FAILURE));
    }

    private static byte[] concat(byte[] head, byte[] tail, int tailLength) {
        byte[] out = Arrays.copyOf(head, head.length + tailLength);
        System.arraycopy(tail, 0, out, head.length, tailLength);
        return out;
    }

    private static byte[] result(int type, int status) {
        return tlv(MANDATORY | type, new byte[] {0, (byte) status});
    }

    static byte[] tlv(int type, byte[] value) {
        byte[] t = new byte[4 + value.length];
        t[0] = (byte) (type >>> 8);
        t[1] = (byte) type;
        t[2] = (byte) (value.length >>> 8);
        t[3] = (byte) value.length;
        System.arraycopy(value, 0, t, 4, value.length);
        return t;
    }

    /** The TLVs of a Phase 2 message that matter here; {@code null} if malformed or an unknown TLV is mandatory. */
    static final class Tlvs {
        int result;
        int intermediate;
        boolean nak;
        byte[] eapPayload;
        byte[] basicAuth;
        byte[] binding; // the whole TLV, header included

        static Tlvs parse(byte[] data) {
            Tlvs t = new Tlvs();
            int at = 0;
            while (at < data.length) {
                if (at + 4 > data.length) {
                    return null;
                }
                int raw = ((data[at] & 0xFF) << 8) | (data[at + 1] & 0xFF);
                int type = raw & 0x3FFF;
                int length = ((data[at + 2] & 0xFF) << 8) | (data[at + 3] & 0xFF);
                if (at + 4 + length > data.length) {
                    return null;
                }
                byte[] value = Arrays.copyOfRange(data, at + 4, at + 4 + length);
                switch (type) {
                    case TLV_RESULT -> t.result = status(value);
                    case TLV_INTERMEDIATE_RESULT -> t.intermediate = status(value);
                    case TLV_NAK -> t.nak = true;
                    case TLV_EAP_PAYLOAD -> t.eapPayload = payload(value);
                    case TLV_BASIC_PASSWORD_AUTH_RESP -> t.basicAuth = value;
                    case TLV_CRYPTO_BINDING -> t.binding = Arrays.copyOfRange(data, at, at + 4 + length);
                    case TLV_IDENTITY_TYPE, TLV_ERROR -> {}
                    default -> {
                        if ((raw & MANDATORY) != 0) {
                            return null; // a mandatory TLV we do not support (§4.3.1)
                        }
                    }
                }
                at += 4 + length;
            }
            return t;
        }

        private static int status(byte[] value) {
            return value.length == 2 ? ((value[0] & 0xFF) << 8) | (value[1] & 0xFF) : FAILURE;
        }

        /** The EAP packet of an EAP-Payload TLV, without TLVs that may follow it inside (§4.2.10). */
        private static byte[] payload(byte[] value) {
            if (value.length < 4) {
                return value;
            }
            int eapLength = ((value[2] & 0xFF) << 8) | (value[3] & 0xFF);
            return eapLength <= value.length ? Arrays.copyOf(value, eapLength) : value;
        }
    }
}
