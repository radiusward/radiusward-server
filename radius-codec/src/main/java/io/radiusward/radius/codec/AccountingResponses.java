/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import org.agrona.MutableDirectBuffer;

/**
 * Builds the Accounting-Response for a received Accounting-Request (RFC 2866 §4.2): same
 * Identifier, every Proxy-State attribute copied in order (RFC 2865 §5.33), signed with the
 * request's authenticator. Allocation-free.
 */
public final class AccountingResponses {

    /** RFC 2865 Proxy-State. */
    public static final int PROXY_STATE = 33;

    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private final RadiusAuthenticator authenticator;

    public AccountingResponses(RadiusAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * Encodes and signs the response into {@code out} at {@code offset}.
     *
     * @param request a validated Accounting-Request
     * @param withMessageAuthenticator whether to add a Message-Authenticator attribute
     * @return length of the response in bytes
     */
    public int encode(
            RadiusPacket request,
            MutableDirectBuffer out,
            int offset,
            byte[] secret,
            boolean withMessageAuthenticator) {
        encoder.wrap(out, offset).header(RadiusCode.ACCOUNTING_RESPONSE, request.identifier());
        int position = request.attributesOffset();
        int end = request.attributesEnd();
        while (position < end) {
            int length = request.buffer().getByte(position + 1) & 0xFF;
            if ((request.buffer().getByte(position) & 0xFF) == PROXY_STATE) {
                encoder.rawAttribute(request.buffer(), position);
            }
            position += length;
        }
        int messageAuthenticator = withMessageAuthenticator ? encoder.messageAuthenticator() : -1;
        int length = encoder.finish();
        authenticator.signResponse(
                out, offset, length, messageAuthenticator, request.buffer(), request.authenticatorOffset(), secret);
        return length;
    }
}
