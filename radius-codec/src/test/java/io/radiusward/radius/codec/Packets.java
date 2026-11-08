/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.agrona.concurrent.UnsafeBuffer;

/** Test helpers for building and wrapping packets. */
final class Packets {

    static final byte[] SECRET = "testing123".getBytes(StandardCharsets.US_ASCII);

    private Packets() {}

    static byte[] hex(String hex) {
        return HexFormat.of().parseHex(hex.replaceAll("\\s+", ""));
    }

    static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    static RadiusPacket wrap(byte[] bytes) {
        RadiusPacket packet = new RadiusPacket();
        packet.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return packet;
    }

    /** Signed Accounting-Request with a few standard attributes and two Cisco VSAs. */
    static byte[] accountingRequest(int identifier, boolean withMessageAuthenticator) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder encoder = new RadiusPacketEncoder().wrap(buffer, 0);
        encoder.header(RadiusCode.ACCOUNTING_REQUEST, identifier)
                .uint32(40, 1) // Acct-Status-Type = Start
                .attribute(44, "session-0001") // Acct-Session-Id
                .ipv4(4, 0x0A000001L) // NAS-IP-Address 10.0.0.1
                .attribute(1, "alice") // User-Name
                .vendorAttribute(9, 1, "ip:addr-pool=default") // Cisco-AVPair
                .attribute(33, "proxy-1") // Proxy-State
                .attribute(33, "proxy-2");
        int ma = withMessageAuthenticator ? encoder.messageAuthenticator() : -1;
        int length = encoder.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, ma, SECRET);
        byte[] out = new byte[length];
        buffer.getBytes(0, out);
        return out;
    }
}
