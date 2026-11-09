/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.util.Arrays;
import org.agrona.DirectBuffer;

/**
 * An EAP packet (RFC 3748 §4): code, identifier, and for requests and responses a type and its data. Carried in RADIUS
 * as one or more {@code EAP-Message} attributes whose values are joined in order (RFC 3579 §3.1).
 */
record EapPacket(int code, int identifier, int type, byte[] data) {

    static final int REQUEST = 1;
    static final int RESPONSE = 2;
    static final int SUCCESS = 3;
    static final int FAILURE = 4;

    static final int TYPE_IDENTITY = 1;
    static final int TYPE_NOTIFICATION = 2;
    static final int TYPE_NAK = 3;
    static final int TYPE_MD5 = 4;

    private static final int EAP_MESSAGE = 79;
    private static final int MAX_LENGTH = 4096;

    /**
     * The EAP packet of a RADIUS request, or {@code null} if there is none or it is malformed (the request is then
     * discarded, RFC 3579 §2.6.2).
     */
    static EapPacket from(RadiusPacket request) {
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

    static EapPacket parse(byte[] p) {
        if (p.length < 4) {
            return null;
        }
        int code = p[0] & 0xFF;
        int length = (p[2] & 0xFF) << 8 | (p[3] & 0xFF);
        if (length != p.length) {
            return null;
        }
        if (code == SUCCESS || code == FAILURE) {
            return length == 4 ? new EapPacket(code, p[1] & 0xFF, 0, new byte[0]) : null;
        }
        if ((code != REQUEST && code != RESPONSE) || length < 5) {
            return null;
        }
        return new EapPacket(code, p[1] & 0xFF, p[4] & 0xFF, Arrays.copyOfRange(p, 5, length));
    }

    byte[] encode() {
        boolean typed = code == REQUEST || code == RESPONSE;
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

    static EapPacket request(int identifier, int type, byte[] data) {
        return new EapPacket(REQUEST, identifier & 0xFF, type, data);
    }

    static EapPacket success(int identifier) {
        return new EapPacket(SUCCESS, identifier & 0xFF, 0, new byte[0]);
    }

    static EapPacket failure(int identifier) {
        return new EapPacket(FAILURE, identifier & 0xFF, 0, new byte[0]);
    }

    /** Writes the packet as {@code EAP-Message} attributes of at most 253 bytes each. */
    void writeTo(RadiusPacketEncoder out) {
        byte[] p = encode();
        for (int off = 0; off < p.length; off += 253) {
            out.attribute(EAP_MESSAGE, Arrays.copyOfRange(p, off, Math.min(p.length, off + 253)));
        }
    }
}
