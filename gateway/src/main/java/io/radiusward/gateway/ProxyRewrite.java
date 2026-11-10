/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.ItemParser;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.util.Arrays;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Per-realm rewriting of proxied packets (ADR 0055): {@code realm.<id>.pre-proxy.remove} drops request attributes
 * before they go to the home server, {@code realm.<id>.pre-proxy.add} adds attributes to it (e.g. Operator-Name),
 * {@code realm.<id>.post-proxy.remove} drops attributes of the home server's answer before it goes to the NAS. Names are
 * resolved and values encoded once, with the gateway's dictionary; the packet path only copies bytes and tests types.
 */
final class ProxyRewrite {

    static final ProxyRewrite NONE = new ProxyRewrite(List.of(), "", List.of());

    /** Never removed: the proxy rebuilds them itself. */
    private static final int[] PROTECTED = {1, 2, 3, 33, 60, 79, 80};

    private final List<String> preRemoveNames;
    private final String preAddText;
    private final List<String> postRemoveNames;
    private boolean[] preRemove = new boolean[256];
    private byte[] preAdd = new byte[0];
    private boolean[] postRemove = new boolean[256];

    ProxyRewrite(List<String> preRemove, String preAdd, List<String> postRemove) {
        this.preRemoveNames = List.copyOf(preRemove);
        this.preAddText = preAdd;
        this.postRemoveNames = List.copyOf(postRemove);
    }

    static ProxyRewrite from(Config config, String prefix) {
        List<String> pre = config.list(prefix + "pre-proxy.remove", List.of());
        String add = config.string(prefix + "pre-proxy.add", "").trim();
        List<String> post = config.list(prefix + "post-proxy.remove", List.of());
        return pre.isEmpty() && add.isEmpty() && post.isEmpty() ? NONE : new ProxyRewrite(pre, add, post);
    }

    boolean any() {
        return this != NONE;
    }

    /** Resolves the names and encodes the added attributes; {@code key} names the realm in errors. */
    void compile(Dictionary dictionary, String key) {
        if (this == NONE) {
            return;
        }
        preRemove = types(dictionary, preRemoveNames, key + "pre-proxy.remove");
        postRemove = types(dictionary, postRemoveNames, key + "post-proxy.remove");
        if (!preAddText.isEmpty()) {
            List<AttributeItem> items;
            try {
                items = ItemParser.parse(preAddText, key + "pre-proxy.add");
            } catch (IllegalArgumentException e) {
                throw new ConfigException(e.getMessage(), e);
            }
            UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
            RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0).header(1, 0);
            for (AttributeItem item : items) {
                AttributeDef def = dictionary.find(item.attribute());
                if (def == null) {
                    throw new ConfigException(key + "pre-proxy.add: unknown attribute " + item.attribute());
                }
                byte[] value;
                try {
                    value = AttributeText.encode(def, item.value());
                } catch (IllegalArgumentException e) {
                    throw new ConfigException(
                            key + "pre-proxy.add: " + item.attribute() + " cannot be " + item.value(), e);
                }
                if (def.vendorId() == 0) {
                    enc.attribute(def.number(), value);
                } else {
                    enc.vendorAttribute(def.vendorId(), def.number(), value);
                }
            }
            int length = enc.finish();
            preAdd = Arrays.copyOfRange(buffer.byteArray(), RadiusPacket.HEADER_LENGTH, length);
        }
    }

    private static boolean[] types(Dictionary dictionary, List<String> names, String key) {
        boolean[] types = new boolean[256];
        for (String raw : names) {
            String name = raw.trim();
            AttributeDef def = dictionary.find(name);
            if (def == null || def.vendorId() != 0 || def.number() > 255) {
                throw new ConfigException(key + ": " + name + " is not a standard attribute");
            }
            for (int p : PROTECTED) {
                if (def.number() == p) {
                    throw new ConfigException(key + ": " + name + " is managed by the proxy");
                }
            }
            types[def.number()] = true;
        }
        return types;
    }

    boolean dropsFromRequest(int type) {
        return preRemove[type];
    }

    boolean dropsFromAnswer(int type) {
        return postRemove[type];
    }

    /** The encoded attributes to add to the request; empty for none. */
    byte[] added() {
        return preAdd;
    }
}
