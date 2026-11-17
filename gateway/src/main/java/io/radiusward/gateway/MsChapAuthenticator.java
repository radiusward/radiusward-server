/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.Md4;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;

/**
 * MS-CHAPv1 and v2 (RFC 2433, RFC 2759) against the user's NT hash, and what the reply carries afterwards: MS-CHAP2-Success
 * with the MPPE keys (RFC 2548, RFC 3079), MS-CHAP-MPPE-Keys for v1, or MS-CHAP-Error for a failure. The MPPE key
 * encryption is shared with EAP, whose MSK is sent the same way.
 */
final class MsChapAuthenticator {

    static final int MICROSOFT = 311;
    private static final int MS_CHAP_RESPONSE = 1;
    private static final int MS_CHAP_ERROR = 2;
    private static final int MS_CHAP_CHALLENGE = 11;
    private static final int MS_CHAP_MPPE_KEYS = 12;
    private static final int MS_MPPE_SEND_KEY = 16;
    private static final int MS_MPPE_RECV_KEY = 17;
    private static final int MS_CHAP2_RESPONSE = 25;
    private static final int MS_CHAP2_SUCCESS = 26;
    private static final int RESPONSE_LENGTH = 50;

    private final SecureRandom saltRandom = new SecureRandom();
    private final Supplier<AuthStores> stores; // replaced by a reload (ADR 0054)
    private final OnceLogger once;

    MsChapAuthenticator(Supplier<AuthStores> stores, OnceLogger once) {
        this.stores = stores;
        this.once = once;
    }

    static boolean isMsChap(int method) {
        return method == AccessRequests.METHOD_MS_CHAP || method == AccessRequests.METHOD_MS_CHAP2;
    }

    /**
     * Verifies MS-CHAPv1 or v2 from the user's NT hash: {@code NT-Password}, or the cleartext password where the
     * store allows it ({@code auth.store.<name>.mschap}). The first usable credential decides.
     */
    boolean verify(AuthRequest auth, int method, UserDirectory.Found found, List<AttributeItem> passwords) {
        AccessContext context = auth.context();
        byte[] ntHash = localNtHash(found, passwords);
        if (ntHash == null) {
            return false;
        }
        Request r = request(context.request(), method);
        if (r == null
                || !java.security.MessageDigest.isEqual(
                        MsChap.challengeResponse(r.challenge(), ntHash), r.ntResponse())) {
            return false;
        }
        succeeded(auth, r, Md4.digest(ntHash));
        return true;
    }

    /** The user's NT hash from its store: NT-Password, or the cleartext where the store allows it; {@code null}. */
    byte[] localNtHash(UserDirectory.Found found, List<AttributeItem> passwords) {
        for (AttributeItem p : passwords) {
            if (p.attribute().equalsIgnoreCase("NT-Password")) {
                byte[] ntHash = MsChap.parseNtPassword(p.value());
                if (ntHash == null) {
                    once.warn(
                            "nt-password:" + found.store(),
                            "store {}: NT-Password is not 32 hex digits; such users are rejected",
                            found.store());
                }
                return ntHash;
            }
            if (p.attribute().equalsIgnoreCase(PasswordCheck.CLEARTEXT)
                    && stores.get().mschap().getOrDefault(found.store(), false)) {
                return MsChap.ntHash(p.value());
            }
        }
        once.warn(
                "mschap:" + found.store(),
                "MS-CHAP request for store {} without NT-Password (or Cleartext-Password with"
                        + " auth.store.<name>.mschap = true): rejected",
                found.store());
        return null;
    }

    /**
     * The parts of an MS-CHAP request a check needs: the 8-byte challenge the NT response answers (v2: the challenge
     * hash), the response, its ident; {@code null} if malformed.
     */
    static final class Request { // not a record: its arrays have no value equality, and it is never compared
        private final byte[] challenge;
        private final byte[] ntResponse;
        private final int ident;
        private final byte[] challengeHash;
        private final boolean v2;

        Request(byte[] challenge, byte[] ntResponse, int ident, byte[] challengeHash, boolean v2) {
            this.challenge = challenge;
            this.ntResponse = ntResponse;
            this.ident = ident;
            this.challengeHash = challengeHash;
            this.v2 = v2;
        }

        byte[] challenge() {
            return challenge;
        }

        byte[] ntResponse() {
            return ntResponse;
        }

        int ident() {
            return ident;
        }

        byte[] challengeHash() {
            return challengeHash;
        }

        boolean v2() {
            return v2;
        }
    }

    /** The MS-CHAP request of {@code request}; {@code null} if malformed. */
    static Request request(RadiusPacket request, int method) {
        byte[] challenge = vendorValue(request, MS_CHAP_CHALLENGE);
        boolean v2 = method == AccessRequests.METHOD_MS_CHAP2;
        byte[] response = vendorValue(request, v2 ? MS_CHAP2_RESPONSE : MS_CHAP_RESPONSE);
        if (challenge == null || response == null || response.length != RESPONSE_LENGTH) {
            return null;
        }
        byte[] ntResponse = Arrays.copyOfRange(response, 26, 50);
        if (v2) {
            if (challenge.length != 16) {
                return null;
            }
            byte[] name = request.octets(1);
            if (name == null) {
                return null; // MS-CHAPv2 hashes the User-Name in
            }
            byte[] hash = MsChap.challengeHash(Arrays.copyOfRange(response, 2, 18), challenge, MsChap.v2UserName(name));
            return new Request(hash, ntResponse, response[0] & 0xFF, hash, true);
        }
        if (challenge.length != 8 || (response[1] & 1) == 0) {
            return null; // without the NT-Response only the LAN Manager response remains: not supported
        }
        return new Request(challenge, ntResponse, response[0] & 0xFF, null, false);
    }

    /** Records a verified MS-CHAP request: the reply proves it to the client ({@link #writeSuccess}). */
    static void succeeded(AuthRequest auth, Request r, byte[] ntHashHash) {
        AuthRequest.MsChapOutcome outcome = auth.msChap;
        outcome.success = true;
        outcome.ident = r.ident();
        outcome.ntHashHash = ntHashHash;
        outcome.ntResponse = r.ntResponse();
        outcome.challengeHash = r.challengeHash();
    }

    /** MS-CHAP2-Success and the MPPE keys (v2), or MS-CHAP-MPPE-Keys (v1). */
    void writeSuccess(AuthRequest auth, int method) {
        AccessContext context = auth.context();
        AuthRequest.MsChapOutcome outcome = auth.msChap;
        if (!outcome.success) {
            return; // not MS-CHAP, or Auth-Type := Accept without a check: nothing to prove to the client
        }
        RadiusPacketEncoder out = context.reply();
        byte[] secret = context.nas().secret();
        byte[] authenticator = new byte[16];
        context.request().buffer().getBytes(context.request().authenticatorOffset(), authenticator);
        if (method == AccessRequests.METHOD_MS_CHAP2) {
            String success =
                    MsChap.authenticatorResponseFromKey(outcome.ntHashHash, outcome.ntResponse, outcome.challengeHash);
            byte[] value = new byte[1 + success.length()];
            value[0] = (byte) outcome.ident;
            System.arraycopy(success.getBytes(StandardCharsets.US_ASCII), 0, value, 1, success.length());
            out.vendorAttribute(MICROSOFT, MS_CHAP2_SUCCESS, value);
            byte[] master = MsChap.masterKeyFromKey(outcome.ntHashHash, outcome.ntResponse);
            writeMppeKeys(context, MsChap.serverKey(master, true), MsChap.serverKey(master, false));
        } else {
            out.vendorAttribute(
                    MICROSOFT,
                    MS_CHAP_MPPE_KEYS,
                    MsChap.encryptV1Keys(new byte[8], outcome.ntHashHash, secret, authenticator));
        }
    }

    /** MS-MPPE-Send-Key and MS-MPPE-Recv-Key, encrypted with the NAS secret under two different salts (RFC 2548). */
    void writeMppeKeys(AccessContext context, byte[] sendKey, byte[] recvKey) {
        byte[] secret = context.nas().secret();
        byte[] authenticator = new byte[16];
        context.request().buffer().getBytes(context.request().authenticatorOffset(), authenticator);
        int salt = saltRandom.nextInt(0x8000) & ~1; // high bit set by salt()
        RadiusPacketEncoder out = context.reply();
        out.vendorAttribute(MICROSOFT, MS_MPPE_SEND_KEY, MsChap.encryptKey(sendKey, secret, authenticator, salt(salt)));
        out.vendorAttribute(
                MICROSOFT, MS_MPPE_RECV_KEY, MsChap.encryptKey(recvKey, secret, authenticator, salt(salt | 1)));
    }

    private static byte[] salt(int value) {
        return new byte[] {(byte) (0x80 | (value >>> 8)), (byte) value};
    }

    /** MS-CHAP-Error "authentication failure" (E=691), no retry; the reason stays in the logs. */
    static void writeError(AccessContext context, int method) {
        RadiusPacket request = context.request();
        byte[] response =
                vendorValue(request, method == AccessRequests.METHOD_MS_CHAP2 ? MS_CHAP2_RESPONSE : MS_CHAP_RESPONSE);
        int ident = response == null || response.length == 0 ? 0 : response[0] & 0xFF;
        String text = "E=691 R=0";
        if (method == AccessRequests.METHOD_MS_CHAP2) {
            byte[] challenge = vendorValue(request, MS_CHAP_CHALLENGE);
            text += " C="
                    + (challenge == null
                            ? ""
                            : HexFormat.of().formatHex(challenge).toUpperCase(Locale.ROOT)) + " V=3";
        }
        byte[] value = new byte[1 + text.length()];
        value[0] = (byte) ident;
        System.arraycopy(text.getBytes(StandardCharsets.US_ASCII), 0, value, 1, text.length());
        context.reply().vendorAttribute(MICROSOFT, MS_CHAP_ERROR, value);
    }

    /** The value of a Microsoft vendor attribute (RFC 2548 layout), or {@code null}. */
    private static byte[] vendorValue(RadiusPacket request, int vendorType) {
        org.agrona.DirectBuffer b = request.buffer();
        for (int pos = request.attributesOffset(); pos + 2 <= request.attributesEnd(); ) {
            int type = b.getByte(pos) & 0xFF;
            int length = b.getByte(pos + 1) & 0xFF;
            if (length < 2) {
                return null;
            }
            if (type == 26 && length >= 8 && b.getInt(pos + 2, java.nio.ByteOrder.BIG_ENDIAN) == MICROSOFT) {
                int vType = b.getByte(pos + 6) & 0xFF;
                int vLength = b.getByte(pos + 7) & 0xFF;
                if (vType == vendorType && vLength >= 2 && 6 + vLength <= length) {
                    byte[] value = new byte[vLength - 2];
                    b.getBytes(pos + 8, value);
                    return value;
                }
            }
            pos += length;
        }
        return null;
    }
}
