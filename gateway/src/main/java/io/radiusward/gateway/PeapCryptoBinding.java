/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * PEAPv0 crypto-binding (MS-PEAP §3.1.5.5, ADR 0032): binds the inner method to the tunnel, so that a man in the middle
 * who relays an inner MS-CHAPv2 exchange through a tunnel of their own cannot complete it. From the tunnel key (first
 * 40 bytes of the TLS keying material) and the inner method's key (ISK) come the IPMK and the compound MAC key (CMK);
 * the Crypto-Binding TLV carries a nonce and a MAC over itself; once both sides have checked it, the MSK is taken from
 * the compound session key instead of the tunnel.
 */
final class PeapCryptoBinding {

    static final int TLV_TYPE = 12;
    /** Type, length, then 56 bytes: reserved, version, received version, subtype, nonce 32, compound MAC 20. */
    static final int TLV_LENGTH = 60;

    private static final int SUBTYPE_REQUEST = 0;
    private static final int SUBTYPE_RESPONSE = 1;

    private final byte[] ipmk;
    private final byte[] cmk;

    /**
     * @param tunnelKey the TLS keying material of the tunnel (its first 40 bytes are used)
     * @param isk the inner method's key: 32 bytes, zeros for a method without keys
     */
    PeapCryptoBinding(byte[] tunnelKey, byte[] isk) {
        this(prfPlus(Arrays.copyOf(tunnelKey, 40), ascii("Inner Methods Compound Keys"), Arrays.copyOf(isk, 32), 60));
    }

    private PeapCryptoBinding(byte[] ipmkAndCmk) {
        ipmk = Arrays.copyOf(ipmkAndCmk, 40);
        cmk = Arrays.copyOfRange(ipmkAndCmk, 40, 60);
    }

    /**
     * Fast reconnect (ADR 0035): no inner method ran, so IPMK and CMK are the tunnel key itself, bytes 0–40 and 40–60
     * (as wpa_supplicant derives them for a resumed session).
     */
    static PeapCryptoBinding fastReconnect(byte[] tunnelKey) {
        return new PeapCryptoBinding(Arrays.copyOf(tunnelKey, 60));
    }

    /** The ISK of an inner MS-CHAPv2 the gateway or a home server accepted: receive key, then send key. */
    static byte[] msChapV2Isk(EapMethod.Inner checked, byte[] ntResponse) {
        byte[] isk = new byte[32];
        System.arraycopy(checked.serverKey(ntResponse, false), 0, isk, 0, 16);
        System.arraycopy(checked.serverKey(ntResponse, true), 0, isk, 16, 16);
        return isk;
    }

    /** The ISK of EAP-MSCHAPv2: the server's receive key, then its send key (as wpa_supplicant and Windows). */
    static byte[] msChapV2Isk(byte[] ntHashHash, byte[] ntResponse) {
        byte[] master = MsChap.masterKeyFromKey(ntHashHash, ntResponse);
        byte[] isk = new byte[32];
        System.arraycopy(MsChap.serverKey(master, false), 0, isk, 0, 16);
        System.arraycopy(MsChap.serverKey(master, true), 0, isk, 16, 16);
        return isk;
    }

    /** The server's Crypto-Binding TLV (subtype request) for this nonce, MAC included. */
    byte[] request(byte[] nonce) {
        byte[] tlv = new byte[TLV_LENGTH];
        tlv[1] = TLV_TYPE;
        tlv[3] = 56;
        tlv[7] = SUBTYPE_REQUEST;
        System.arraycopy(nonce, 0, tlv, 8, 32);
        System.arraycopy(mac(tlv), 0, tlv, 40, 20);
        return tlv;
    }

    /**
     * Whether the peer's TLV answers ours: version 0, subtype response, our nonce, a MAC that matches. MS-PEAP has the
     * peer set the nonce's last bit, wpa_supplicant echoes it unchanged: both are accepted (the subtype and the MAC
     * already keep our own TLV from being reflected).
     */
    boolean verifies(byte[] tlv, byte[] nonce) {
        if (tlv.length != TLV_LENGTH
                || (tlv[0] & 0x3F) != 0
                || tlv[1] != TLV_TYPE
                || tlv[2] != 0
                || tlv[3] != 56
                || tlv[4] != 0
                || tlv[5] != 0
                || tlv[6] != 0
                || tlv[7] != SUBTYPE_RESPONSE) {
            return false;
        }
        byte[] peerNonce = Arrays.copyOfRange(tlv, 8, 40);
        peerNonce[31] &= (byte) 0xFE;
        if (!MessageDigest.isEqual(peerNonce, nonce)) {
            return false;
        }
        byte[] zeroed = tlv.clone();
        Arrays.fill(zeroed, 40, 60, (byte) 0);
        return MessageDigest.isEqual(Arrays.copyOfRange(tlv, 40, 60), mac(zeroed));
    }

    /** The MSK once the binding is checked: the first 64 bytes of the compound session key. */
    byte[] msk() {
        return Arrays.copyOf(prfPlus(ipmk, ascii("Session Key Generating Function"), new byte[1], 128), 64);
    }

    /** Compound MAC: HMAC-SHA1(CMK, the TLV with a zero MAC | EAP type 25). */
    byte[] mac(byte[] tlvWithZeroMac) {
        Mac hmac = hmac(cmk);
        hmac.update(tlvWithZeroMac);
        hmac.update((byte) Peap.TYPE);
        return hmac.doFinal();
    }

    /** PEAPv0 PRF+: T(n) = HMAC-SHA1(K, T(n-1) | label | seed | n | 0x00 | 0x00), T(0) empty. */
    static byte[] prfPlus(byte[] key, byte[] label, byte[] seed, int length) {
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        Mac hmac = hmac(key);
        for (int n = 1, at = 0; at < length; n++) {
            hmac.update(t);
            hmac.update(label);
            hmac.update(seed);
            hmac.update(new byte[] {(byte) n, 0, 0});
            t = hmac.doFinal();
            System.arraycopy(t, 0, out, at, Math.min(t.length, length - at));
            at += t.length;
        }
        return out;
    }

    private static Mac hmac(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA1 is part of every JDK", e);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }
}
