/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;

/**
 * Builds Access-Accept, Access-Reject and Access-Challenge for an Access-Request (RFC 2865 §4). Every reply carries a
 * Message-Authenticator as its <b>first</b> attribute (RFC 3579 §3.2; the BlastRADIUS mitigation, CVE-2024-3596),
 * then the given reply attributes, then every Proxy-State of the request in order (RFC 2865 §5.33); it is signed
 * with the request's authenticator. Allocation-free.
 */
public final class AccessResponses {

    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private final RadiusAuthenticator authenticator;

    public AccessResponses(RadiusAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * Encodes and signs a reply into {@code out} at {@code offset}.
     *
     * @param code {@link RadiusCode#ACCESS_ACCEPT}, {@link RadiusCode#ACCESS_REJECT} or
     *     {@link RadiusCode#ACCESS_CHALLENGE}
     * @param attributes encoded reply attributes (type, length, value …), without Message-Authenticator and
     *     Proxy-State; {@code attributesLength} 0 for none
     * @return length of the reply in bytes
     * @throws IllegalArgumentException for another code; {@link IllegalStateException} if the reply exceeds 4096
     *     bytes (a policy error, not request data)
     */
    public int encode(
            RadiusPacket request,
            int code,
            DirectBuffer attributes,
            int attributesOffset,
            int attributesLength,
            MutableDirectBuffer out,
            int offset,
            byte[] secret) {
        if (code != RadiusCode.ACCESS_ACCEPT
                && code != RadiusCode.ACCESS_REJECT
                && code != RadiusCode.ACCESS_CHALLENGE) {
            throw new IllegalArgumentException("not an Access-Request reply code: " + code);
        }
        encoder.wrap(out, offset).header(code, request.identifier());
        int messageAuthenticator = encoder.messageAuthenticator();
        if (attributesLength > 0) {
            encoder.rawAttributes(attributes, attributesOffset, attributesLength);
        }
        DirectBuffer buffer = request.buffer();
        for (int position = request.attributesOffset(); position < request.attributesEnd(); ) {
            int length = buffer.getByte(position + 1) & 0xFF;
            if ((buffer.getByte(position) & 0xFF) == AccountingResponses.PROXY_STATE) {
                encoder.rawAttribute(buffer, position);
            }
            position += length;
        }
        int length = encoder.finish();
        authenticator.signResponse(
                out, offset, length, messageAuthenticator, buffer, request.authenticatorOffset(), secret);
        return length;
    }
}
