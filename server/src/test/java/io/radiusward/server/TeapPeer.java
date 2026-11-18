/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

/**
 * The inner side of a TEAPv1 peer for tests (RFC 7170): Basic-Password-Auth-Resp or a NAK to it, an inner EAP-GTC
 * (Nak to any other inner method), and the Crypto-Binding answered with its MSK Compound MAC, chained over identity
 * types as the server asks. The server's binding is checked, and the MSK derived as the peer does.
 */
final class TeapPeer implements UnaryOperator<byte[]> {

    private static final int BINDING_LENGTH = 80;
    private static final int MAC_AT = 4 + 4 + 32 + 20;

    private final String user;
    private final String password;
    EapTlsClient client;
    /** The server's Outer TLVs of its Start (the default Authority-ID). */
    byte[] serverOuterTlvs = Teap.tlv(Teap.TLV_AUTHORITY_ID, EapConfig.DEFAULT_AUTHORITY_ID);
    /** The Outer TLVs of the peer's first message, for the Compound MAC. */
    byte[] outerTlvs = new byte[0];
    /** Answer Basic-Password-Auth-Req with a NAK TLV. */
    boolean nakBasic;
    /** The value of the Basic-Password-Auth-Resp instead of the user's name and password; {@code null}: those. */
    byte[] basicAuthValue;
    /** Changes the binding response before its MAC is computed. */
    Consumer<byte[]> bindingTamper = b -> {};
    /** A Compound MAC that does not match. */
    boolean wrongMac;
    /** Rewrites each whole answer (TLVs left out, added or broken). */
    UnaryOperator<byte[]> rewrite = a -> a;
    /** What the peer answers to a failed Result. */
    byte[] failureAnswer = Teap.tlv(Teap.MANDATORY | Teap.TLV_RESULT, new byte[] {0, Teap.FAILURE});
    /** Never answers inside the tunnel (only acknowledgements go out). */
    boolean silent;

    int basicAnswers;
    int bindings;
    int result;
    boolean serverBindingValid = true;
    byte[] msk;

    private TeapKeys keys;
    private byte[] simck;

    TeapPeer(String user, String password) {
        this.user = user;
        this.password = password;
    }

    @Override
    public byte[] apply(byte[] in) {
        if (silent || in.length == 0) {
            return null; // in TEAP the server speaks first inside the tunnel
        }
        try {
            return rewrite.apply(answer(in));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] answer(byte[] in) throws Exception {
        byte[] binding = null;
        boolean resultAsked = false;
        boolean basicAsked = false;
        byte[] eap = null;
        for (int at = 0; at + 4 <= in.length; ) {
            int type = ((in[at] & 0xFF) << 8 | (in[at + 1] & 0xFF)) & 0x3FFF;
            int length = (in[at + 2] & 0xFF) << 8 | (in[at + 3] & 0xFF);
            byte[] value = Arrays.copyOfRange(in, at + 4, at + 4 + length);
            switch (type) {
                case Teap.TLV_RESULT -> {
                    result = value[1];
                    resultAsked = true;
                }
                case Teap.TLV_CRYPTO_BINDING -> binding = Arrays.copyOfRange(in, at, at + 4 + length);
                case Teap.TLV_BASIC_PASSWORD_AUTH_REQ -> basicAsked = true;
                case Teap.TLV_EAP_PAYLOAD -> eap = value;
                default -> {}
            }
            at += 4 + length;
        }
        if (result == Teap.FAILURE) {
            return failureAnswer;
        }
        if (binding != null) {
            return bind(binding, resultAsked);
        }
        if (basicAsked) {
            basicAnswers++;
            if (nakBasic) {
                // Vendor-Id 0, then the NAK-Type: the TLV refused
                return Teap.tlv(
                        Teap.MANDATORY | Teap.TLV_NAK, new byte[] {0, 0, 0, 0, 0, Teap.TLV_BASIC_PASSWORD_AUTH_REQ});
            }
            return Teap.tlv(Teap.MANDATORY | Teap.TLV_BASIC_PASSWORD_AUTH_RESP, basicAuth());
        }
        if (eap != null) {
            return Teap.tlv(Teap.MANDATORY | Teap.TLV_EAP_PAYLOAD, inner(EapPacket.parse(eap)));
        }
        throw new IllegalStateException("nothing to answer");
    }

    private byte[] basicAuth() {
        if (basicAuthValue != null) {
            return basicAuthValue;
        }
        byte[] name = user.getBytes(StandardCharsets.UTF_8);
        byte[] pass = password.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(name.length);
        out.writeBytes(name);
        out.write(pass.length);
        out.writeBytes(pass);
        return out.toByteArray();
    }

    /** Identity, then EAP-GTC; a Nak to any other method. */
    private byte[] inner(EapPacket request) {
        byte[] data;
        int type = request.type();
        if (type == EapPacket.TYPE_IDENTITY) {
            data = user.getBytes(StandardCharsets.UTF_8);
        } else if (type == InnerEap.GTC) {
            data = password.getBytes(StandardCharsets.UTF_8);
        } else {
            type = EapPacket.TYPE_NAK;
            data = new byte[] {InnerEap.GTC};
        }
        return new EapPacket(EapPacket.CODE_RESPONSE, request.identifier(), type, data).encode();
    }

    /** The server's binding checked; the response with this round's keys (no inner MSK: Basic or GTC). */
    private byte[] bind(byte[] request, boolean resultAsked) throws Exception {
        bindings++;
        if (simck == null) {
            simck = client.export("EXPORTER: teap session key seed", TeapKeys.SIMCK_LENGTH);
            keys = new TeapKeys(client.cipherSuite());
        }
        TeapKeys.Compound compound = keys.next(simck, null, null);
        byte[] expected = keys.compoundMac(compound.cmk(), request, serverOuterTlvs, outerTlvs);
        serverBindingValid &= request.length == BINDING_LENGTH
                && MessageDigest.isEqual(expected, Arrays.copyOfRange(request, MAC_AT, BINDING_LENGTH));
        byte[] response = request.clone();
        response[7] = (byte) ((2 << 4) | 1); // MSK Compound MAC; Sub-Type 1: response
        response[8 + 31] |= 1; // the server's nonce with its last bit set
        bindingTamper.accept(response);
        byte[] mac = keys.compoundMac(compound.cmk(), response, serverOuterTlvs, outerTlvs);
        if (wrongMac) {
            mac[0] ^= 1;
        }
        System.arraycopy(mac, 0, response, MAC_AT, mac.length);
        simck = compound.simck();
        msk = keys.msk(simck);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(Teap.tlv(Teap.MANDATORY | Teap.TLV_INTERMEDIATE_RESULT, new byte[] {0, Teap.SUCCESS}));
        if (resultAsked) {
            out.writeBytes(Teap.tlv(Teap.MANDATORY | Teap.TLV_RESULT, new byte[] {0, Teap.SUCCESS}));
        }
        out.writeBytes(response);
        return out.toByteArray();
    }
}
