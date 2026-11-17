/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.attributes.Ietf;
import io.radiusward.radius.codec.attributes.Microsoft;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.UnaryOperator;

/**
 * The inner side of an EAP-TTLS peer for tests: PAP, CHAP or MS-CHAPv2 AVPs, the server's MS-CHAP2-Success checked;
 * optionally one more AVP after the credentials.
 */
final class TtlsPeer implements UnaryOperator<byte[]> {

    private final String user;
    private final String password;
    private final boolean msChapV2;
    private final boolean wrongChallenge;
    EapTlsClient client;
    byte[] challengeHash;
    byte[] ntResponse;
    boolean serverProved;
    /** CHAP with the tunnel's implicit challenge (RFC 5281 §11.2.2) instead of PAP. */
    boolean chap;
    /** An AVP sent after the credentials, {@code null} for none. */
    byte[] extraAvp;

    TtlsPeer(String user, String password, boolean msChapV2, boolean wrongChallenge) {
        this.user = user;
        this.password = password;
        this.msChapV2 = msChapV2;
        this.wrongChallenge = wrongChallenge;
    }

    @Override
    public byte[] apply(byte[] in) {
        try {
            return in.length == 0 ? credentials() : success(in);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] credentials() throws Exception {
        byte[] avps = avps();
        return extraAvp == null ? avps : concat(avps, extraAvp);
    }

    private byte[] avps() throws Exception {
        byte[] name = user.getBytes(StandardCharsets.UTF_8);
        if (chap) {
            byte[] implicit = client.export("ttls challenge", 17);
            byte[] challenge = Arrays.copyOf(implicit, 16);
            java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5");
            md5.update(implicit[16]);
            md5.update(password.getBytes(StandardCharsets.UTF_8));
            md5.update(challenge);
            byte[] chapPassword = concat(new byte[] {implicit[16]}, md5.digest());
            return concat(
                    Ttls.avp(Ietf.USER_NAME, 0, name),
                    Ttls.avp(Ietf.CHAP_CHALLENGE, 0, challenge),
                    Ttls.avp(Ietf.CHAP_PASSWORD, 0, chapPassword));
        }
        if (!msChapV2) {
            byte[] padded = Arrays.copyOf(
                    password.getBytes(StandardCharsets.UTF_8),
                    ((password.length() + 15) / 16) * 16); // zero padding to 16 (RFC 5281 §11.2.5)
            return concat(Ttls.avp(Ietf.USER_NAME, 0, name), Ttls.avp(Ietf.USER_PASSWORD, 0, padded));
        }
        byte[] implicit = client.export("ttls challenge", 17);
        if (wrongChallenge) {
            new SecureRandom().nextBytes(implicit);
        }
        byte[] challenge = Arrays.copyOf(implicit, 16);
        byte[] peer = new byte[16];
        new SecureRandom().nextBytes(peer);
        challengeHash = MsChap.challengeHash(peer, challenge, MsChap.v2UserName(name));
        ntResponse = MsChap.challengeResponse(challengeHash, MsChap.ntHash(password));
        byte[] response = new byte[50];
        response[0] = implicit[16];
        System.arraycopy(peer, 0, response, 2, 16);
        System.arraycopy(ntResponse, 0, response, 26, 24);
        return concat(
                Ttls.avp(Ietf.USER_NAME, 0, name),
                Ttls.avp(Microsoft.CHAP_CHALLENGE, Microsoft.VENDOR_ID, challenge),
                Ttls.avp(Microsoft.CHAP2_RESPONSE, Microsoft.VENDOR_ID, response));
    }

    /** MS-CHAP2-Success: check S=, then acknowledge with no data. */
    private byte[] success(byte[] in) {
        ByteBuffer b = ByteBuffer.wrap(in);
        int code = b.getInt(0);
        int length = b.getInt(4) & 0xFFFFFF;
        if (code == Microsoft.CHAP2_SUCCESS && length > 12) {
            String text = new String(in, 13, length - 13, StandardCharsets.US_ASCII);
            serverProved =
                    text.equals(MsChap.authenticatorResponse(MsChap.ntHash(password), ntResponse, challengeHash));
        }
        return new byte[0];
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }
}
