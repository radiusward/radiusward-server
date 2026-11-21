/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.eap.MsChap;
import io.radiusward.eap.TtlsAvp;
import io.radiusward.radius.codec.attributes.Ietf;
import io.radiusward.radius.codec.attributes.Microsoft;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import javax.net.ssl.SSLException;

/**
 * EAP-TTLS inside the tunnel (RFC 5281): the user and its credential as AVPs: PAP, CHAP or MS-CHAP with the
 * tunnel's implicit challenge, or MS-CHAPv2 with the server's MS-CHAP2-Success checked.
 */
final class TtlsInner implements UnaryOperator<byte[]> {

    private final EapLogin login;
    private final Supplier<TlsPeer> tls;
    private byte[] challengeHash;
    private byte[] ntResponse;

    TtlsInner(EapLogin login, Supplier<TlsPeer> tls) {
        this.login = login;
        this.tls = tls;
    }

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
                EapBytes.concat(
                        user,
                        TtlsAvp.encode(
                                Ietf.USER_PASSWORD, 0, Arrays.copyOf(password, (password.length + 15) / 16 * 16)));
            case CHAP -> {
                byte[] implicit = tls.get().export("ttls challenge", 17);
                byte[] challenge = Arrays.copyOf(implicit, 16);
                yield EapBytes.concat(
                        user,
                        TtlsAvp.encode(Ietf.CHAP_CHALLENGE, 0, challenge),
                        TtlsAvp.encode(
                                Ietf.CHAP_PASSWORD,
                                0,
                                Credentials.chapPassword(implicit[16] & 0xFF, password, challenge)));
            }
            case MSCHAP -> {
                byte[] implicit = tls.get().export("ttls challenge", 9);
                byte[] challenge = Arrays.copyOf(implicit, 8);
                byte[] response = new byte[50]; // ident, flags (1: the NT response counts), LM response, NT response
                response[0] = implicit[8];
                response[1] = 1;
                System.arraycopy(
                        MsChap.challengeResponse(challenge, MsChap.ntHash(login.password)), 0, response, 26, 24);
                yield EapBytes.concat(
                        user,
                        TtlsAvp.encode(Microsoft.CHAP_CHALLENGE, Microsoft.VENDOR_ID, challenge),
                        TtlsAvp.encode(Microsoft.CHAP_RESPONSE, Microsoft.VENDOR_ID, response));
            }
            case MSCHAPV2 -> {
                byte[] implicit = tls.get().export("ttls challenge", 17);
                byte[] challenge = Arrays.copyOf(implicit, 16);
                byte[] peer = new byte[16];
                EapBytes.RANDOM.nextBytes(peer);
                challengeHash = MsChap.challengeHash(peer, challenge, MsChap.v2UserName(name));
                ntResponse = MsChap.challengeResponse(challengeHash, MsChap.ntHash(login.password));
                byte[] response = new byte[50];
                response[0] = implicit[16];
                System.arraycopy(peer, 0, response, 2, 16);
                System.arraycopy(ntResponse, 0, response, 26, 24);
                yield EapBytes.concat(
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
            serverProved =
                    text.equals(MsChap.authenticatorResponse(MsChap.ntHash(login.password), ntResponse, challengeHash));
            if (!serverProved) {
                throw new IllegalStateException("the server's MS-CHAPv2 authenticator response does not verify");
            }
        }
        return new byte[0];
    }
}
