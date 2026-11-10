/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Chargeable-User-Identity (RFC 4372, ADR 0056): a stable pseudonym of the authenticated user for the operator that
 * asks, so roaming partners can bill and correlate sessions without learning who the user is. The value is
 * HMAC-SHA-256 over the user name (the inner one for tunnels) and the request's Operator-Name, keyed with
 * {@code auth.cui.key}, as 32 hex digits: the same user gets the same CUI from the same operator, different operators
 * get unrelated ones.
 *
 * @param always {@code auth.cui.mode = always}: every Access-Accept; otherwise only when the NAS asks by sending the
 *     attribute (RFC 4372 §2.1: a single NUL byte)
 */
record Cui(byte[] key, boolean always) {

    static final int CHARGEABLE_USER_IDENTITY = 89;
    static final int OPERATOR_NAME = 126;

    /** {@code auth.cui.*}; {@code null} without {@code auth.cui.key}. */
    static Cui from(Config config) {
        String key = config.string("auth.cui.key", "").trim();
        if (key.isEmpty()) {
            return null;
        }
        if (key.length() < 16) {
            throw new ConfigException("auth.cui.key: at least 16 characters (it hides who the users are)");
        }
        String mode = config.string("auth.cui.mode", "requested").trim().toLowerCase(Locale.ROOT);
        if (!mode.equals("requested") && !mode.equals("always")) {
            throw new ConfigException("auth.cui.mode: requested or always");
        }
        return new Cui(key.getBytes(StandardCharsets.UTF_8), mode.equals("always"));
    }

    /** Adds the CUI to {@code reply} when wanted and the reply has none yet (a store's own CUI wins). */
    void apply(RadiusPacket request, String user, List<AttributeItem> reply) {
        if (!always && request.findAttribute(CHARGEABLE_USER_IDENTITY) < 0) {
            return;
        }
        for (AttributeItem r : reply) {
            if (r.attribute().equalsIgnoreCase("Chargeable-User-Identity")) {
                return;
            }
        }
        int at = request.findAttribute(OPERATOR_NAME);
        String operator = at < 0
                ? ""
                : request.buffer()
                        .getStringWithoutLengthUtf8(at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
        reply.add(new AttributeItem("Chargeable-User-Identity", "=", value(user, operator)));
    }

    String value(String user, String operator) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(user.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
            mac.update((byte) 0);
            mac.update(operator.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(mac.doFinal(), 0, 16);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
