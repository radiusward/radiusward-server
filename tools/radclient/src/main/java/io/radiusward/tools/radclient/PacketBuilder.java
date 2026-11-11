/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.VendorDef;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;

/** Builds and signs Accounting-Requests and Access-Requests from {@code Name=Value} pairs using the dictionary. */
final class PacketBuilder {

    private final Dictionary dictionary;
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private final int code;
    private int messageAuthenticator = -1;

    PacketBuilder(Dictionary dictionary, int identifier) {
        this(dictionary, RadiusCode.ACCOUNTING_REQUEST, identifier);
    }

    PacketBuilder(Dictionary dictionary, int code, int identifier) {
        this.dictionary = dictionary;
        this.code = code;
        encoder.wrap(buffer, 0).header(code, identifier);
    }

    /** The Request Authenticator of an Access-Request: random, chosen before the password is encrypted with it. */
    PacketBuilder authenticator(byte[] authenticator) {
        encoder.authenticator(authenticator);
        return this;
    }

    /** For attributes the dictionary cannot express, such as encrypted credentials. */
    RadiusPacketEncoder encoder() {
        return encoder;
    }

    /** Adds {@code Name=Value}; the name may be a path such as {@code Cisco.AVPair}. */
    PacketBuilder add(String assignment) {
        int eq = assignment.indexOf('=');
        if (eq <= 0) {
            throw new UsageException("attribute must be Name=Value: " + assignment);
        }
        return add(
                assignment.substring(0, eq).trim(), assignment.substring(eq + 1).trim());
    }

    PacketBuilder add(String name, String value) {
        AttributeDef def = dictionary.find(name);
        if (def == null) {
            throw new UsageException("unknown attribute " + name);
        }
        byte[] bytes = encode(def, value);
        if (def.vendorId() != 0) {
            VendorDef vendor = def.vendor();
            if (!vendor.isStandardFormat()
                    || !def.parent().type().equals(io.radiusward.radius.dictionary.DataType.VENDOR)) {
                throw new UsageException(def.path() + ": only standard-format vendor attributes are supported");
            }
            encoder.vendorAttribute(def.vendorId(), def.number(), bytes);
        } else if (def.isTopLevel()) {
            encoder.attribute(def.number(), bytes);
        } else {
            throw new UsageException(def.path() + ": nested attributes are not supported");
        }
        return this;
    }

    PacketBuilder messageAuthenticator() {
        messageAuthenticator = encoder.messageAuthenticator();
        return this;
    }

    /**
     * Finishes and signs the request: an Access-Request keeps its authenticator and gets its Message-Authenticator,
     * other requests get both computed.
     */
    byte[] build(byte[] secret) {
        if (code == RadiusCode.ACCESS_REQUEST && messageAuthenticator < 0) {
            messageAuthenticator();
        }
        int length = encoder.finish();
        if (code == RadiusCode.ACCESS_REQUEST) {
            new RadiusAuthenticator().signAccessRequest(buffer, 0, length, messageAuthenticator, secret);
        } else {
            new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, messageAuthenticator, secret);
        }
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    static byte[] encode(AttributeDef def, String text) {
        try {
            return io.radiusward.radius.codec.AttributeText.encode(def, text);
        } catch (IllegalArgumentException e) {
            throw new UsageException(e.getMessage());
        }
    }
}
