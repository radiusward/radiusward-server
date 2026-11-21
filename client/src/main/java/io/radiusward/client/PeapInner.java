/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.auth.Md4;
import io.radiusward.eap.EapPacket;
import io.radiusward.eap.MsChap;
import io.radiusward.eap.PeapCryptoBinding;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import javax.net.ssl.SSLException;

/**
 * PEAPv0 inside the tunnel, as Windows behaves: the inner identity, EAP-MSCHAPv2 with the server's authenticator
 * response checked or EAP-GTC, a Nak for another method; then the Result TLV and, if the server sent one, the
 * Crypto-Binding TLV, checked and answered.
 */
final class PeapInner implements UnaryOperator<byte[]> {

    private static final int TLV = 33; // PEAP's EAP-TLV inside the tunnel

    private final EapLogin login;
    private final Supplier<TlsPeer> tls;
    private byte[] challengeHash;
    private byte[] ntResponse;

    PeapInner(EapLogin login, Supplier<TlsPeer> tls) {
        this.login = login;
        this.tls = tls;
    }

    boolean serverProved;
    byte[] boundMsk;

    @Override
    public byte[] apply(byte[] in) {
        if (in.length == 0) {
            return null; // in PEAP the server speaks first inside the tunnel
        }
        EapPacket tlv = EapPacket.parse(in); // EAP-TLV is a whole EAP packet; the rest has no header
        if (tlv != null && tlv.code() == EapPacket.CODE_REQUEST && tlv.type() == TLV) {
            return result(tlv);
        }
        int type = in[0] & 0xFF;
        int wanted = login.inner == EapLogin.Inner.GTC ? EapPacket.TYPE_GTC : EapPacket.TYPE_MSCHAPV2;
        if (type == EapPacket.TYPE_IDENTITY) {
            return typed(type, login.user.getBytes(StandardCharsets.UTF_8));
        }
        if (type == EapPacket.TYPE_GTC && wanted == type) {
            return typed(type, login.password.getBytes(StandardCharsets.UTF_8));
        }
        if (type == EapPacket.TYPE_MSCHAPV2 && wanted == type) {
            return msChapV2(in);
        }
        return new byte[] {EapPacket.TYPE_NAK, (byte) wanted};
    }

    private byte[] msChapV2(byte[] in) {
        int op = in[1];
        int id = in[2] & 0xFF;
        if (op == 1) { // Challenge: value size, 16-byte challenge, server name
            byte[] authChallenge = Arrays.copyOfRange(in, 6, 22);
            byte[] peer = new byte[16];
            EapBytes.RANDOM.nextBytes(peer);
            byte[] name = login.user.getBytes(StandardCharsets.UTF_8);
            challengeHash = MsChap.challengeHash(peer, authChallenge, MsChap.v2UserName(name));
            ntResponse = MsChap.challengeResponse(challengeHash, MsChap.ntHash(login.password));
            int msLength = 4 + 1 + 49 + name.length;
            byte[] out = new byte[1 + msLength];
            out[0] = (byte) EapPacket.TYPE_MSCHAPV2;
            out[1] = 2;
            out[2] = (byte) id;
            out[3] = (byte) (msLength >>> 8);
            out[4] = (byte) msLength;
            out[5] = 49;
            System.arraycopy(peer, 0, out, 6, 16);
            System.arraycopy(ntResponse, 0, out, 30, 24);
            System.arraycopy(name, 0, out, 55, name.length);
            return out;
        }
        if (op == 3) { // Success: the server proves it knew the password before the device accepts it
            String text = new String(in, 5, in.length - 5, StandardCharsets.US_ASCII);
            serverProved = challengeHash != null
                    && text.startsWith(
                            MsChap.authenticatorResponse(MsChap.ntHash(login.password), ntResponse, challengeHash));
            if (!serverProved) {
                throw new IllegalStateException("the server's MS-CHAPv2 authenticator response does not verify");
            }
            return new byte[] {(byte) EapPacket.TYPE_MSCHAPV2, 3};
        }
        return new byte[] {(byte) EapPacket.TYPE_MSCHAPV2, 4}; // Failure acknowledged
    }

    /** The Result TLV echoed, and the Crypto-Binding TLV answered if the server sent one. */
    private byte[] result(EapPacket request) {
        byte[] tlvs = request.data();
        int status = 2;
        byte[] binding = null;
        for (int at = 0; at + 4 <= tlvs.length; ) {
            int type = ((tlvs[at] & 0x3F) << 8) | (tlvs[at + 1] & 0xFF);
            int length = ((tlvs[at + 2] & 0xFF) << 8) | (tlvs[at + 3] & 0xFF);
            if (at + 4 + length > tlvs.length) {
                break;
            }
            if (type == 3 && length == 2) {
                status = tlvs[at + 5] & 0xFF;
            } else if (type == PeapCryptoBinding.TLV_TYPE) {
                binding = Arrays.copyOfRange(tlvs, at, at + 4 + length);
            }
            at += 4 + length;
        }
        byte[] result = {(byte) 0x80, 3, 0, 2, 0, (byte) status};
        byte[] answer = new byte[0];
        if (binding != null && status == 1) {
            try {
                byte[] isk = login.inner == EapLogin.Inner.MSCHAPV2 && ntResponse != null
                        ? PeapCryptoBinding.msChapV2Isk(Md4.digest(MsChap.ntHash(login.password)), ntResponse)
                        : new byte[32];
                PeapCryptoBinding cb =
                        new PeapCryptoBinding(tls.get().msk(EapPacket.TYPE_PEAP, "client EAP encryption"), isk);
                answer = cb.answer(binding);
                if (answer == null) {
                    throw new IllegalStateException("the server's PEAP crypto-binding does not verify");
                }
                boundMsk = cb.msk();
            } catch (SSLException e) {
                throw new IllegalStateException("cannot derive the tunnel key: " + e.getMessage(), e);
            }
        }
        return EapPacket.response(request.identifier(), TLV, EapBytes.concat(result, answer))
                .encode();
    }

    private static byte[] typed(int type, byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) type;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }
}
