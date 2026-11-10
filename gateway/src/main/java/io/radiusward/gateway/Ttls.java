/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.net.ssl.SSLException;

/**
 * EAP-TTLSv0 (RFC 5281, ADR 0030, 0040): a TLS tunnel that authenticates the server; inside it the client sends
 * Diameter AVPs — User-Name and User-Password (PAP), CHAP-Challenge and CHAP-Password (CHAP), MS-CHAP-Challenge and
 * MS-CHAP-Response (MS-CHAPv1) or MS-CHAP2-Response (MS-CHAPv2) — or EAP-Message AVPs with a whole inner EAP
 * conversation ({@link InnerEap}: EAP-MSCHAPv2, EAP-GTC, EAP-MD5 from {@code auth.eap.ttls.inner}). The CHAP and
 * MS-CHAP challenges are not sent: both sides derive them from the tunnel ({@code ttls challenge}: 17 bytes, challenge
 * and ident, for CHAP and MS-CHAPv2; 9 bytes for MS-CHAPv1; §11.1), and a client that answers another one is refused.
 * PAP, CHAP and MS-CHAPv1 succeed at once; MS-CHAPv2 sends MS-CHAP2-Success and succeeds when the client acknowledges
 * it. Keys: {@code ttls keying material} (TLS 1.2), type 21 (TLS 1.3, RFC 9427).
 */
final class Ttls extends TlsTunnel {

    static final int TYPE = 21;
    static final int USER_NAME = 1;
    static final int USER_PASSWORD = 2;
    static final int CHAP_PASSWORD = 3;
    static final int CHAP_CHALLENGE = 60;
    static final int EAP_MESSAGE = 79;
    static final int MICROSOFT = 311;
    static final int MS_CHAP_RESPONSE = 1;
    static final int MS_CHAP_CHALLENGE = 11;
    static final int MS_CHAP2_RESPONSE = 25;
    static final int MS_CHAP2_SUCCESS = 26;
    static final int FLAG_VENDOR = 0x80;
    static final int FLAG_MANDATORY = 0x40;

    private byte[] implicitChallenge;
    private String user;
    private String authenticated;
    private boolean successSent;
    private byte[][] pending; // an inner check that could not be answered: user name, and the AVP values
    private int pendingKind;
    private final java.util.List<Integer> innerEapTypes;
    private InnerEap innerEap; // once the client sent an EAP-Message

    private static final int PAP = 1;
    private static final int CHAP = 2;
    private static final int MS_CHAP_V1 = 3;
    private static final int MS_CHAP_V2 = 4;

    Ttls(EapTlsConfig config) {
        this(config, java.util.List.of(InnerEap.MS_CHAP_V2, InnerEap.GTC, InnerEap.MD5));
    }

    /** @param innerEapTypes the EAP types offered inside the tunnel, first preferred ({@code auth.eap.ttls.inner}) */
    Ttls(EapTlsConfig config, java.util.List<Integer> innerEapTypes) {
        super(config);
        this.innerEapTypes = java.util.List.copyOf(innerEapTypes);
    }

    @Override
    public int type() {
        return TYPE;
    }

    @Override
    boolean clientCertificate() {
        return false;
    }

    /** TTLSv0 (RFC 5281 §9.1: the only version). */
    @Override
    int version() {
        return 0;
    }

    @Override
    String keyLabel() {
        return "ttls keying material";
    }

    @Override
    public String innerIdentity() {
        return authenticated;
    }

    @Override
    byte[] onFinished(boolean tls13) {
        return null; // the client speaks first inside the tunnel
    }

    @Override
    boolean succeedsOnResumption() {
        authenticated = remembered(); // RFC 5281 §8: a resumed session may skip phase 2, as wpa_supplicant does
        return authenticated != null;
    }

    @Override
    Step onAck(Credentials credentials) {
        if (successSent) {
            remember(authenticated);
            return Step.succeeded(msk()); // the client acknowledged MS-CHAP2-Success
        }
        return Step.FAILED; // the client must send its credentials
    }

    @Override
    Step onData(byte[] data, Credentials credentials) {
        if (successSent || credentials.inner() == null) {
            return Step.FAILED;
        }
        byte[] name = null;
        byte[] password = null;
        byte[] challenge = null;
        byte[] response = null;
        byte[] chapChallenge = null;
        byte[] chapPassword = null;
        byte[] msChapResponse = null;
        java.io.ByteArrayOutputStream eap = null;
        int at = 0;
        while (at + 8 <= data.length) {
            int code = ((data[at] & 0xFF) << 24)
                    | ((data[at + 1] & 0xFF) << 16)
                    | ((data[at + 2] & 0xFF) << 8)
                    | (data[at + 3] & 0xFF);
            int flags = data[at + 4] & 0xFF;
            int length = ((data[at + 5] & 0xFF) << 16) | ((data[at + 6] & 0xFF) << 8) | (data[at + 7] & 0xFF);
            int header = (flags & FLAG_VENDOR) != 0 ? 12 : 8;
            if (length < header || at + length > data.length) {
                return Step.FAILED;
            }
            int vendor = header == 12
                    ? ((data[at + 8] & 0xFF) << 24)
                            | ((data[at + 9] & 0xFF) << 16)
                            | ((data[at + 10] & 0xFF) << 8)
                            | (data[at + 11] & 0xFF)
                    : 0;
            byte[] value = Arrays.copyOfRange(data, at + header, at + length);
            if (vendor == 0 && code == USER_NAME) {
                name = value;
            } else if (vendor == 0 && code == USER_PASSWORD) {
                password = value;
            } else if (vendor == MICROSOFT && code == MS_CHAP_CHALLENGE) {
                challenge = value;
            } else if (vendor == MICROSOFT && code == MS_CHAP2_RESPONSE) {
                response = value;
            } else if (vendor == MICROSOFT && code == MS_CHAP_RESPONSE) {
                msChapResponse = value;
            } else if (vendor == 0 && code == CHAP_CHALLENGE) {
                chapChallenge = value;
            } else if (vendor == 0 && code == CHAP_PASSWORD) {
                chapPassword = value;
            } else if (vendor == 0 && code == EAP_MESSAGE) {
                if (eap == null) {
                    eap = new java.io.ByteArrayOutputStream();
                }
                eap.writeBytes(value); // a long EAP packet comes in several AVPs
            } else if ((flags & FLAG_MANDATORY) != 0) {
                return Step.FAILED; // a mandatory AVP we do not understand (RFC 5281 §10.1)
            }
            at += (length + 3) & ~3;
        }
        if (eap != null) {
            return innerEap(eap.toByteArray(), credentials);
        }
        if (name == null || innerEap != null) {
            return Step.FAILED;
        }
        user = new String(name, StandardCharsets.UTF_8);
        if (password != null) {
            return pap(trimNuls(password), credentials);
        }
        if (chapChallenge != null && chapPassword != null) {
            return chap(chapChallenge, chapPassword, credentials);
        }
        if (challenge != null && response != null) {
            return msChapV2(challenge, response, credentials);
        }
        if (challenge != null && msChapResponse != null) {
            return msChapV1(challenge, msChapResponse, credentials);
        }
        return Step.FAILED;
    }

    @Override
    Step onRetry(Credentials credentials) {
        if (innerEap != null) {
            return afterInnerEap(innerEap.retry(credentials));
        }
        if (pending == null) {
            return Step.FAILED;
        }
        return switch (pendingKind) {
            case PAP -> pap(pending[0], credentials);
            case CHAP -> chap(pending[0], pending[1], credentials);
            case MS_CHAP_V1 -> msChapV1(pending[0], pending[1], credentials);
            default -> msChapV2(pending[0], pending[1], credentials);
        };
    }

    /** EAP inside the tunnel (§11.2.4): the inner conversation's next request, or its outcome as the method's. */
    private Step innerEap(byte[] packet, Credentials credentials) {
        if (innerEap == null) {
            if (innerEapTypes.isEmpty()) {
                return Step.FAILED;
            }
            innerEap = new InnerEap(innerEapTypes);
        }
        return afterInnerEap(innerEap.handle(packet, credentials));
    }

    private Step afterInnerEap(Step inner) {
        if (inner.unavailable()) {
            return Step.UNAVAILABLE;
        }
        if (!inner.done()) {
            return sendApplication(avp(EAP_MESSAGE, 0, inner.request()));
        }
        if (!inner.success()) {
            return Step.FAILED;
        }
        authenticated = innerEap.identity();
        remember(authenticated);
        return Step.succeeded(msk());
    }

    /** CHAP (§11.2.2): the challenge is the tunnel's 16 bytes, the CHAP identifier its 17th. */
    private Step chap(byte[] challenge, byte[] chapPassword, Credentials credentials) {
        byte[] implicit = implicitChallenge();
        if (implicit == null
                || chapPassword.length != 17
                || !MessageDigest.isEqual(challenge, Arrays.copyOf(implicit, 16))
                || chapPassword[0] != implicit[16]) {
            return Step.FAILED;
        }
        Inner checked = credentials
                .inner()
                .chap(user, chapPassword[0] & 0xFF, challenge, Arrays.copyOfRange(chapPassword, 1, 17));
        return decided(checked, CHAP, challenge, chapPassword);
    }

    /** MS-CHAPv1 (§11.2.3): the challenge is the tunnel's first 8 of 9 bytes, the ident its 9th. */
    private Step msChapV1(byte[] challenge, byte[] response, Credentials credentials) {
        byte[] implicit;
        try {
            implicit = export("ttls challenge", 9); // its own length: TLS 1.3 exports differ by length
        } catch (SSLException e) {
            return Step.FAILED;
        }
        // ident, flags (1: use the NT response), LM response 24, NT response 24
        if (response.length != 50
                || response[1] != 1
                || !MessageDigest.isEqual(challenge, Arrays.copyOf(implicit, 8))
                || response[0] != implicit[8]) {
            return Step.FAILED;
        }
        Inner checked = credentials.inner().msChapV1(user, challenge, Arrays.copyOfRange(response, 26, 50));
        return decided(checked, MS_CHAP_V1, challenge, response);
    }

    /** A check that succeeds at once, or waits for the retransmission when it could not be made. */
    private Step decided(Inner checked, int kind, byte[]... values) {
        if (checked.code() == AccessHandler.DROP) {
            pending = values;
            pendingKind = kind;
            return Step.UNAVAILABLE;
        }
        pending = null;
        if (checked.code() != AccessHandler.ACCEPT) {
            return Step.FAILED;
        }
        authenticated = user;
        remember(user);
        return Step.succeeded(msk());
    }

    private Step pap(byte[] password, Credentials credentials) {
        Inner checked = credentials.inner().password(user, password);
        if (checked.code() == AccessHandler.DROP) {
            pending = new byte[][] {password};
            pendingKind = PAP;
            return Step.UNAVAILABLE;
        }
        pending = null;
        if (checked.code() != AccessHandler.ACCEPT) {
            return Step.FAILED;
        }
        authenticated = user;
        remember(user);
        return Step.succeeded(msk());
    }

    private Step msChapV2(byte[] challenge, byte[] response, Credentials credentials) {
        byte[] implicit = implicitChallenge();
        // the challenge and the response's ident must be the ones derived from this tunnel (§11.2.4)
        if (implicit == null
                || response.length != 50
                || !MessageDigest.isEqual(challenge, Arrays.copyOf(implicit, 16))
                || response[0] != implicit[16]) {
            return Step.FAILED;
        }
        byte[] peer = Arrays.copyOfRange(response, 2, 18);
        byte[] ntResponse = Arrays.copyOfRange(response, 26, 50);
        byte[] hash = MsChap.challengeHash(peer, challenge, MsChap.v2UserName(user.getBytes(StandardCharsets.UTF_8)));
        Inner checked = credentials
                .inner()
                .msChapV2(user, new EapMethod.MsChapV2(hash, ntResponse, challenge, peer, response[0] & 0xFF));
        if (checked.code() == AccessHandler.DROP) {
            pending = new byte[][] {challenge, response};
            pendingKind = MS_CHAP_V2;
            return Step.UNAVAILABLE;
        }
        pending = null;
        if (checked.code() != AccessHandler.ACCEPT || !checked.keyed()) {
            return Step.FAILED;
        }
        authenticated = user;
        successSent = true;
        String s = checked.authenticatorResponse(ntResponse, hash);
        byte[] value = new byte[1 + s.length()];
        value[0] = response[0];
        System.arraycopy(s.getBytes(StandardCharsets.US_ASCII), 0, value, 1, s.length());
        return sendApplication(avp(MS_CHAP2_SUCCESS, MICROSOFT, value));
    }

    /** {@code ttls challenge} from the tunnel: 16 bytes of challenge and the ident; {@code null} if not available. */
    private byte[] implicitChallenge() {
        if (implicitChallenge == null) {
            try {
                implicitChallenge = export("ttls challenge", 17);
            } catch (SSLException e) {
                return null;
            }
        }
        return implicitChallenge;
    }

    /** A Diameter AVP, vendor-specific when {@code vendor} is set, padded to 4 bytes. */
    static byte[] avp(int code, int vendor, byte[] value) {
        int header = vendor != 0 ? 12 : 8;
        int length = header + value.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(code >>> 24);
        out.write(code >>> 16);
        out.write(code >>> 8);
        out.write(code);
        out.write((vendor != 0 ? FLAG_VENDOR : 0) | FLAG_MANDATORY);
        out.write(length >>> 16);
        out.write(length >>> 8);
        out.write(length);
        if (vendor != 0) {
            out.write(vendor >>> 24);
            out.write(vendor >>> 16);
            out.write(vendor >>> 8);
            out.write(vendor);
        }
        out.writeBytes(value);
        while (out.size() % 4 != 0) {
            out.write(0);
        }
        return out.toByteArray();
    }

    /** A PAP password may be padded with zero bytes to a multiple of 16 (§11.2.5). */
    private static byte[] trimNuls(byte[] password) {
        int n = password.length;
        while (n > 0 && password[n - 1] == 0) {
            n--;
        }
        return Arrays.copyOf(password, n);
    }
}
