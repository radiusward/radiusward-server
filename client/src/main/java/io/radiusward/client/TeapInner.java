/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.eap.EapPacket;
import io.radiusward.eap.TeapKeys;
import io.radiusward.eap.TeapTlv;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import javax.net.ssl.SSLException;

/**
 * TEAPv1 inside the tunnel (RFC 7170, RFC 9930): Basic-Password-Auth-Resp, or an inner EAP-GTC (a Nak to any other
 * inner method); each Crypto-Binding of the server checked and answered with the MSK Compound MAC, the keys chained
 * as the server does; the MSK from the last S-IMCK.
 */
final class TeapInner implements UnaryOperator<byte[]> {

    private final EapLogin login;
    private final Supplier<TlsPeer> tls;
    private TeapKeys keys;
    private byte[] simck;

    TeapInner(EapLogin login, Supplier<TlsPeer> tls) {
        this.login = login;
        this.tls = tls;
    }

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
                        TeapTlv.MANDATORY | TeapTlv.NAK, new byte[] {0, 0, 0, 0, 0, TeapTlv.BASIC_PASSWORD_AUTH_REQ});
            }
            byte[] name = login.user.getBytes(StandardCharsets.UTF_8);
            byte[] pass = login.password.getBytes(StandardCharsets.UTF_8);
            return TeapTlv.encode(
                    TeapTlv.MANDATORY | TeapTlv.BASIC_PASSWORD_AUTH_RESP,
                    EapBytes.concat(new byte[] {(byte) name.length}, name, new byte[] {(byte) pass.length}, pass));
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
            simck = tls.get().export("EXPORTER: teap session key seed", TeapKeys.SIMCK_LENGTH);
            keys = new TeapKeys(tls.get().cipherSuite());
        }
        byte[] serverOuter = tls.get().serverOuterTlvs();
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
        return EapBytes.concat(intermediate, result, response);
    }
}
