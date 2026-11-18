/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static io.radiusward.radius.codec.attributes.Ietf.CHAP_CHALLENGE;
import static io.radiusward.radius.codec.attributes.Ietf.CHAP_PASSWORD;
import static io.radiusward.radius.codec.attributes.Ietf.MESSAGE_AUTHENTICATOR;
import static io.radiusward.radius.codec.attributes.Ietf.PROXY_STATE;
import static io.radiusward.radius.codec.attributes.Ietf.TUNNEL_PASSWORD;
import static io.radiusward.radius.codec.attributes.Ietf.USER_NAME;
import static io.radiusward.radius.codec.attributes.Ietf.USER_PASSWORD;
import static io.radiusward.radius.codec.attributes.Ietf.VENDOR_SPECIFIC;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.attributes.Microsoft;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * How a proxied request and its answer are rewritten (ADR 0037, ADR 0055): the request for the home server and the
 * answer for the NAS, with the secrets of each side, in the proxy's slot buffers. Our Proxy-State carries a token of
 * this gateway, the slot and its generation, so an answer finds its request. Allocation-free; used by the proxy's
 * thread only.
 */
final class ProxyCodec {

    private final UnsafeBuffer packets;
    private final UnsafeBuffer ourAuthenticators;
    private final UnsafeBuffer nasAuthenticators;
    private final UnsafeBuffer reply;
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final AccessRequests credentials = new AccessRequests();
    private final SaltedValues salted = new SaltedValues();
    private final SecureRandom random = new SecureRandom();
    private final byte[] token = new byte[8]; // Proxy-State: 4 random bytes of this gateway, slot, generation
    private final UnsafeBuffer plain = new UnsafeBuffer(new byte[256]);
    private final UnsafeBuffer cipher = new UnsafeBuffer(new byte[256]);
    private final byte[] authScratch = new byte[16];

    /**
     * @param packets the requests, {@link RadiusPacket#MAX_LENGTH} per slot
     * @param ourAuthenticators the Request Authenticators we sent, 16 bytes per slot
     * @param nasAuthenticators the NAS's Request Authenticators, 16 bytes per slot
     * @param reply where answers for the NAS are written
     */
    ProxyCodec(
            UnsafeBuffer packets, UnsafeBuffer ourAuthenticators, UnsafeBuffer nasAuthenticators, UnsafeBuffer reply) {
        this.packets = packets;
        this.ourAuthenticators = ourAuthenticators;
        this.nasAuthenticators = nasAuthenticators;
        this.reply = reply;
        random.nextBytes(token);
    }

    /**
     * The request to the home server, into the slot's place in the packet buffer: User-Password encrypted for the
     * home server, the User-Name stripped if the realm says so, CHAP's challenge kept, the realm's rewrites, our
     * Proxy-State and a Message-Authenticator. Its length, or -1 if it does not fit or the password cannot be read.
     */
    int request(
            RadiusPacket request,
            ProxyConfig.Realm realm,
            byte[] nasSecret,
            byte[] homeSecret,
            int slot,
            int generation,
            int id) {
        UnsafeBuffer out = packets;
        int o = slot * RadiusPacket.MAX_LENGTH;
        int end = o + RadiusPacket.MAX_LENGTH;
        out.putByte(o, (byte) RadiusCode.ACCESS_REQUEST);
        out.putByte(o + 1, (byte) id);
        random.nextBytes(authScratch);
        out.putBytes(o + 4, authScratch);
        out.getBytes(o + 4, ourAuthenticators, slot * 16, 16);
        int w = o + RadiusPacket.HEADER_LENGTH;
        int ma = w;
        out.putByte(w, (byte) MESSAGE_AUTHENTICATOR);
        out.putByte(w + 1, (byte) 18);
        out.setMemory(w + 2, 16, (byte) 0);
        w += 18;
        DirectBuffer in = request.buffer();
        boolean chap = false;
        boolean challenge = false;
        for (int at = request.attributesOffset(); at < request.attributesEnd(); ) {
            int type = in.getByte(at) & 0xFF;
            int l = in.getByte(at + 1) & 0xFF;
            if (type == MESSAGE_AUTHENTICATOR || realm.rewrite().dropsFromRequest(type)) {
                at += l;
                continue;
            }
            if (type == USER_PASSWORD) {
                int n = credentials.decryptUserPassword(request, nasSecret, plain, 0);
                if (n < 0) {
                    return -1;
                }
                int c = credentials.encryptUserPassword(plain, 0, n, out, o + 4, homeSecret, cipher, 0);
                if (w + 2 + c > end) {
                    return -1;
                }
                out.putByte(w, (byte) USER_PASSWORD);
                out.putByte(w + 1, (byte) (2 + c));
                out.putBytes(w + 2, cipher, 0, c);
                w += 2 + c;
            } else if (type == USER_NAME && realm.strip()) {
                int start = at + 2;
                int stop = at + l;
                for (int i = at + 2; i < at + l; i++) {
                    byte b = in.getByte(i);
                    if (b == '@') {
                        stop = i;
                        break;
                    }
                    if (b == '\\' && start == at + 2) {
                        start = i + 1;
                    }
                }
                if (w + 2 + (stop - start) > end) {
                    return -1;
                }
                out.putByte(w, (byte) USER_NAME);
                out.putByte(w + 1, (byte) (2 + stop - start));
                out.putBytes(w + 2, in, start, stop - start);
                w += 2 + stop - start;
            } else {
                chap |= type == CHAP_PASSWORD;
                challenge |= type == CHAP_CHALLENGE;
                if (w + l > end) {
                    return -1;
                }
                out.putBytes(w, in, at, l);
                w += l;
            }
            at += l;
        }
        if (chap && !challenge) { // the original Request Authenticator was the challenge (RFC 2865 §2.2)
            if (w + 18 > end) {
                return -1;
            }
            out.putByte(w, (byte) CHAP_CHALLENGE);
            out.putByte(w + 1, (byte) 18);
            out.putBytes(w + 2, in, request.authenticatorOffset(), 16);
            w += 18;
        }
        byte[] added = realm.rewrite().added();
        if (added.length > 0) {
            if (w + added.length > end) {
                return -1;
            }
            out.putBytes(w, added);
            w += added.length;
        }
        if (w + 10 > end) {
            return -1;
        }
        out.putByte(w, (byte) PROXY_STATE);
        out.putByte(w + 1, (byte) 10);
        out.putBytes(w + 2, token, 0, 4);
        out.putShort(w + 6, (short) slot, ByteOrder.BIG_ENDIAN);
        out.putShort(w + 8, (short) generation, ByteOrder.BIG_ENDIAN);
        w += 10;
        int len = w - o;
        out.putShort(o + 2, (short) len, ByteOrder.BIG_ENDIAN);
        authenticator.signAccessRequest(out, o, len, ma, homeSecret);
        return len;
    }

    /**
     * The home server's answer for the NAS, into the reply buffer: our Proxy-State and the attributes the realm drops
     * removed, MPPE keys and Tunnel-Password re-encrypted for the NAS, signed with its secret. Its length, or -1.
     */
    int answer(
            RadiusPacket response,
            int code,
            int nasIdentifier,
            ProxyConfig.Realm realm,
            byte[] homeSecret,
            byte[] nasSecret,
            int slot) {
        reply.putByte(0, (byte) code);
        reply.putByte(1, (byte) nasIdentifier);
        int w = RadiusPacket.HEADER_LENGTH;
        reply.putByte(w, (byte) MESSAGE_AUTHENTICATOR);
        reply.putByte(w + 1, (byte) 18);
        reply.setMemory(w + 2, 16, (byte) 0);
        w += 18;
        DirectBuffer in = response.buffer();
        for (int at = response.attributesOffset(); at < response.attributesEnd(); ) {
            int type = in.getByte(at) & 0xFF;
            int l = in.getByte(at + 1) & 0xFF;
            boolean ours = type == PROXY_STATE && l == 10 && sameToken(in, at + 2, slot);
            boolean dropped = realm != null && realm.rewrite().dropsFromAnswer(type);
            if (type != MESSAGE_AUTHENTICATOR && !ours && !dropped) {
                if (w + l > RadiusPacket.MAX_LENGTH) {
                    return -1;
                }
                reply.putBytes(w, in, at, l);
                if (!reencrypt(type, w, l, homeSecret, nasSecret, slot)) {
                    return -1;
                }
                w += l;
            }
            at += l;
        }
        reply.putShort(2, (short) w, ByteOrder.BIG_ENDIAN);
        authenticator.signResponse(reply, 0, w, RadiusPacket.HEADER_LENGTH, nasAuthenticators, slot * 16, nasSecret);
        return w;
    }

    private boolean sameToken(DirectBuffer in, int at, int slot) {
        for (int i = 0; i < 4; i++) {
            if (in.getByte(at + i) != token[i]) {
                return false;
            }
        }
        return (in.getShort(at + 4, ByteOrder.BIG_ENDIAN) & 0xFFFF) == slot;
    }

    /** MS-MPPE-Send/Recv-Key and Tunnel-Password, copied to the reply at {@code w}, for the NAS's secret. */
    private boolean reencrypt(int type, int w, int l, byte[] homeSecret, byte[] nasSecret, int slot) {
        if (type == TUNNEL_PASSWORD && l > 3) {
            return salted.reencrypt(
                    reply,
                    w + 3,
                    l - 3,
                    homeSecret,
                    ourAuthenticators,
                    slot * 16,
                    nasSecret,
                    nasAuthenticators,
                    slot * 16);
        }
        if (type == VENDOR_SPECIFIC && l > 8 && reply.getInt(w + 2, ByteOrder.BIG_ENDIAN) == Microsoft.VENDOR_ID) {
            for (int p = w + 6; p + 2 <= w + l; ) {
                int sub = reply.getByte(p) & 0xFF;
                int sl = reply.getByte(p + 1) & 0xFF;
                if (sl < 2 || p + sl > w + l) {
                    return false;
                }
                if ((sub == Microsoft.MPPE_SEND_KEY || sub == Microsoft.MPPE_RECV_KEY)
                        && !salted.reencrypt(
                                reply,
                                p + 2,
                                sl - 2,
                                homeSecret,
                                ourAuthenticators,
                                slot * 16,
                                nasSecret,
                                nasAuthenticators,
                                slot * 16)) {
                    return false;
                }
                p += sl;
            }
        }
        return true;
    }
}
