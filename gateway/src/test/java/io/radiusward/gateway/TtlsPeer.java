/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.UnaryOperator;

/** The inner side of an EAP-TTLS peer for tests: PAP or MS-CHAPv2 AVPs, the server's MS-CHAP2-Success checked. */
final class TtlsPeer implements UnaryOperator<byte[]> {

    private final String user;
    private final String password;
    private final boolean msChapV2;
    private final boolean wrongChallenge;
    EapTlsClient client;
    byte[] challengeHash;
    byte[] ntResponse;
    boolean serverProved;

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
        byte[] name = user.getBytes(StandardCharsets.UTF_8);
        if (!msChapV2) {
            byte[] padded = Arrays.copyOf(
                    password.getBytes(StandardCharsets.UTF_8),
                    ((password.length() + 15) / 16) * 16); // zero padding to 16 (RFC 5281 §11.2.5)
            return concat(Ttls.avp(Ttls.USER_NAME, 0, name), Ttls.avp(Ttls.USER_PASSWORD, 0, padded));
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
                Ttls.avp(Ttls.USER_NAME, 0, name),
                Ttls.avp(Ttls.MS_CHAP_CHALLENGE, Ttls.MICROSOFT, challenge),
                Ttls.avp(Ttls.MS_CHAP2_RESPONSE, Ttls.MICROSOFT, response));
    }

    /** MS-CHAP2-Success: check S=, then acknowledge with no data. */
    private byte[] success(byte[] in) {
        ByteBuffer b = ByteBuffer.wrap(in);
        int code = b.getInt(0);
        int length = b.getInt(4) & 0xFFFFFF;
        if (code == Ttls.MS_CHAP2_SUCCESS && length > 12) {
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
