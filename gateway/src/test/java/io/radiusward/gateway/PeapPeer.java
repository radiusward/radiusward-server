/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.UnaryOperator;

/**
 * The inner side of a PEAPv0 peer for tests, as Windows behaves: identity, EAP-MSCHAPv2 with the server's
 * authenticator response checked, Result TLV answered.
 */
final class PeapPeer implements UnaryOperator<byte[]> {

    private final String identity;
    private final String password;
    byte[] challengeHash;
    byte[] ntResponse;
    boolean serverProved;
    boolean failureSeen;

    PeapPeer(String identity, String password) {
        this.identity = identity;
        this.password = password;
    }

    @Override
    public byte[] apply(byte[] in) {
        if (in.length == 0) {
            return null; // in PEAP the server speaks first inside the tunnel
        }
        EapPacket tlv = EapPacket.parse(in); // a full EAP packet of type 33 first: its code 1 looks like Identity
        if (tlv != null && tlv.code() == EapPacket.REQUEST && tlv.type() == Peap.TLV) {
            byte[] out = in.clone();
            out[0] = EapPacket.RESPONSE;
            return out; // echo the Result TLV with the same status
        }
        int type = in[0] & 0xFF;
        if (type == EapPacket.TYPE_IDENTITY) {
            byte[] name = identity.getBytes(StandardCharsets.UTF_8);
            byte[] out = new byte[1 + name.length];
            out[0] = EapPacket.TYPE_IDENTITY;
            System.arraycopy(name, 0, out, 1, name.length);
            return out;
        }
        if (type == Peap.MS_CHAP_V2) {
            int op = in[1];
            int id = in[2] & 0xFF;
            if (op == 1) { // Challenge: value-size, 16-byte challenge, server name
                byte[] authChallenge = Arrays.copyOfRange(in, 6, 22);
                byte[] peer = new byte[16];
                new SecureRandom().nextBytes(peer);
                byte[] name = identity.getBytes(StandardCharsets.UTF_8);
                challengeHash = MsChap.challengeHash(peer, authChallenge, MsChap.v2UserName(name));
                ntResponse = MsChap.challengeResponse(challengeHash, MsChap.ntHash(password));
                int msLength = 4 + 1 + 49 + name.length;
                byte[] out = new byte[1 + msLength];
                out[0] = (byte) Peap.MS_CHAP_V2;
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
            if (op == 3) { // Success: check S= before accepting the server
                String text = new String(in, 5, in.length - 5, StandardCharsets.US_ASCII);
                String expected = MsChap.authenticatorResponse(MsChap.ntHash(password), ntResponse, challengeHash);
                serverProved = text.startsWith(expected);
                return serverProved ? new byte[] {(byte) Peap.MS_CHAP_V2, 3} : null;
            }
            if (op == 4) {
                failureSeen = true;
                return new byte[] {(byte) Peap.MS_CHAP_V2, 4};
            }
        }
        return null;
    }
}
