/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

import static io.radiusward.radius.codec.attributes.Ietf.EAP_MESSAGE;

import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.util.Arrays;
import org.agrona.DirectBuffer;

/**
 * An EAP packet (RFC 3748 §4): code, identifier, and for requests and responses a type and its data. Carried in RADIUS
 * as one or more {@code EAP-Message} attributes whose values are joined in order (RFC 3579 §3.1).
 */
public record EapPacket(int code, int identifier, int type, byte[] data) {

    public static final int CODE_REQUEST = 1;
    public static final int CODE_RESPONSE = 2;
    public static final int CODE_SUCCESS = 3;
    public static final int CODE_FAILURE = 4;

    public static final int TYPE_IDENTITY = 1;
    public static final int TYPE_NOTIFICATION = 2;
    public static final int TYPE_NAK = 3;
    public static final int TYPE_MD5 = 4;
    public static final int TYPE_GTC = 6;
    public static final int TYPE_TLS = 13;
    public static final int TYPE_SIM = 18;
    public static final int TYPE_TTLS = 21;
    public static final int TYPE_AKA = 23;
    public static final int TYPE_PEAP = 25;
    public static final int TYPE_MSCHAPV2 = 26;
    public static final int TYPE_AKA_PRIME = 50;
    public static final int TYPE_PWD = 52;
    public static final int TYPE_TEAP = 55;

    private static final int MAX_LENGTH = 4096;

    /**
     * The EAP packet of a RADIUS request, or {@code null} if there is none or it is malformed (the request is then
     * discarded, RFC 3579 §2.6.2).
     */
    public static EapPacket from(RadiusPacket request) {
        DirectBuffer b = request.buffer();
        byte[] joined = new byte[MAX_LENGTH];
        int n = 0;
        for (int pos = request.attributesOffset(); pos + 2 <= request.attributesEnd(); ) {
            int length = b.getByte(pos + 1) & 0xFF;
            if (length < 2) {
                return null;
            }
            if ((b.getByte(pos) & 0xFF) == EAP_MESSAGE) {
                if (n + length - 2 > MAX_LENGTH) {
                    return null;
                }
                b.getBytes(pos + 2, joined, n, length - 2);
                n += length - 2;
            }
            pos += length;
        }
        return n == 0 ? null : parse(Arrays.copyOf(joined, n));
    }

    public static EapPacket parse(byte[] p) {
        if (p.length < 4) {
            return null;
        }
        int code = p[0] & 0xFF;
        int length = (p[2] & 0xFF) << 8 | (p[3] & 0xFF);
        if (length != p.length) {
            return null;
        }
        if (code == CODE_SUCCESS || code == CODE_FAILURE) {
            return length == 4 ? new EapPacket(code, p[1] & 0xFF, 0, new byte[0]) : null;
        }
        if ((code != CODE_REQUEST && code != CODE_RESPONSE) || length < 5) {
            return null;
        }
        return new EapPacket(code, p[1] & 0xFF, p[4] & 0xFF, Arrays.copyOfRange(p, 5, length));
    }

    public byte[] encode() {
        boolean typed = code == CODE_REQUEST || code == CODE_RESPONSE;
        byte[] p = new byte[(typed ? 5 : 4) + data.length];
        p[0] = (byte) code;
        p[1] = (byte) identifier;
        p[2] = (byte) (p.length >>> 8);
        p[3] = (byte) p.length;
        if (typed) {
            p[4] = (byte) type;
            System.arraycopy(data, 0, p, 5, data.length);
        }
        return p;
    }

    public static EapPacket request(int identifier, int type, byte[] data) {
        return new EapPacket(CODE_REQUEST, identifier & 0xFF, type, data);
    }

    /** A peer's response to request {@code identifier}. */
    public static EapPacket response(int identifier, int type, byte[] data) {
        return new EapPacket(CODE_RESPONSE, identifier & 0xFF, type, data);
    }

    public static EapPacket success(int identifier) {
        return new EapPacket(CODE_SUCCESS, identifier & 0xFF, 0, new byte[0]);
    }

    public static EapPacket failure(int identifier) {
        return new EapPacket(CODE_FAILURE, identifier & 0xFF, 0, new byte[0]);
    }

    /** Writes the packet as {@code EAP-Message} attributes of at most 253 bytes each. */
    public void writeTo(RadiusPacketEncoder out) {
        byte[] p = encode();
        for (int off = 0; off < p.length; off += 253) {
            out.attribute(EAP_MESSAGE, Arrays.copyOfRange(p, off, Math.min(p.length, off + 253)));
        }
    }

    /** Equal when code, identifier, type and the data's content are (a record compares arrays by reference). */
    @Override
    public boolean equals(Object o) {
        return o instanceof EapPacket p
                && code == p.code
                && identifier == p.identifier
                && type == p.type
                && Arrays.equals(data, p.data);
    }

    @Override
    public int hashCode() {
        return 31 * (31 * (31 * code + identifier) + type) + Arrays.hashCode(data);
    }

    /** The header and the data's length, not its content: it may carry a password or key material. */
    @Override
    public String toString() {
        return "EapPacket[code=" + code + ", identifier=" + identifier + ", type=" + type + ", data="
                + (data == null ? 0 : data.length) + " bytes]";
    }
}
