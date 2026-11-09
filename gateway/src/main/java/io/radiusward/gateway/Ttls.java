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
 * EAP-TTLSv0 (RFC 5281, ADR 0030): a TLS tunnel that authenticates the server; inside it the client sends Diameter
 * AVPs — User-Name and either User-Password (PAP) or MS-CHAP-Challenge and MS-CHAP2-Response (MS-CHAPv2). The
 * MS-CHAPv2 challenge is not sent: both sides derive it from the tunnel ({@code ttls challenge}, 17 bytes: challenge
 * and ident, §11.1), and a client that answers another one is refused. PAP succeeds at once; MS-CHAPv2 sends
 * MS-CHAP2-Success and succeeds when the client acknowledges it. Keys: {@code ttls keying material} (TLS 1.2), type 21
 * (TLS 1.3, RFC 9427).
 */
final class Ttls extends TlsTunnel {

    static final int TYPE = 21;
    static final int USER_NAME = 1;
    static final int USER_PASSWORD = 2;
    static final int MICROSOFT = 311;
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

    Ttls(EapTlsConfig config) {
        super(config);
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
            } else if ((flags & FLAG_MANDATORY) != 0) {
                return Step.FAILED; // a mandatory AVP we do not understand (RFC 5281 §10.1)
            }
            at += (length + 3) & ~3;
        }
        if (name == null) {
            return Step.FAILED;
        }
        user = new String(name, StandardCharsets.UTF_8);
        if (password != null) {
            return pap(trimNuls(password), credentials);
        }
        if (challenge != null && response != null) {
            return msChapV2(challenge, response, credentials);
        }
        return Step.FAILED;
    }

    @Override
    Step onRetry(Credentials credentials) {
        if (pending == null) {
            return Step.FAILED;
        }
        return pending.length == 1 ? pap(pending[0], credentials) : msChapV2(pending[0], pending[1], credentials);
    }

    private Step pap(byte[] password, Credentials credentials) {
        Inner checked = credentials.inner().password(user, password);
        if (checked.code() == AccessHandler.DROP) {
            pending = new byte[][] {password};
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
        Inner checked = credentials.inner().msChapV2(user, hash, ntResponse);
        if (checked.code() == AccessHandler.DROP) {
            pending = new byte[][] {challenge, response};
            return Step.UNAVAILABLE;
        }
        pending = null;
        if (checked.code() != AccessHandler.ACCEPT || checked.ntHashHash() == null) {
            return Step.FAILED;
        }
        authenticated = user;
        successSent = true;
        String s = MsChap.authenticatorResponseFromKey(checked.ntHashHash(), ntResponse, hash);
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
