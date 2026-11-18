/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.auth.AttributeItem;
import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import org.agrona.collections.IntHashSet;
import org.agrona.collections.Object2ObjectHashMap;

/**
 * Turns the reply items of a user and its groups into Access-Accept attributes: group items merged under the user's,
 * each distinct item encoded once and cached per worker, vendor attributes only for NAS entries of that vendor
 * (counted per NAS entry when left out). Items that cannot be sent are warned about once and skipped.
 */
final class ReplyEncoder {

    private final Dictionary dictionary;
    private final OnceLogger once;
    /** Per NAS entry with a vendor filter; replaced as a whole by a reload, otherwise only read. */
    private volatile Map<String, AtomicLong> filtered;

    /** @param filteredNas the NAS entries with a vendor filter ({@link AuthStores#replyVendors()}) */
    ReplyEncoder(Dictionary dictionary, OnceLogger once, Set<String> filteredNas) {
        this.dictionary = dictionary;
        this.once = once;
        this.filtered = counters(filteredNas, Map.of());
    }

    /** Adds group reply items: {@code +=} always, {@code =} and {@code :=} only if the user did not set it. */
    static void merge(List<AttributeItem> reply, List<AttributeItem> group) {
        for (AttributeItem item : group) {
            boolean set = reply.stream().anyMatch(r -> r.attribute().equalsIgnoreCase(item.attribute()));
            if (item.op().equals("+=") || !set) {
                reply.add(item);
            }
        }
    }

    /**
     * Writes the reply items a NAS entry may receive: standard attributes always, vendor attributes only of {@code
     * vendors}. Each distinct item is encoded once and kept in {@code encoded}, at most {@code cacheMax} of them.
     *
     * @param vendors the vendors the NAS entry receives attributes of; {@code null}: all
     */
    void encode(
            Object2ObjectHashMap<AttributeItem, Encoded> encoded,
            List<AttributeItem> reply,
            RadiusPacketEncoder out,
            IntHashSet vendors,
            String nas,
            int cacheMax) {
        for (AttributeItem item : reply) {
            Encoded e = encoded.get(item);
            if (e == null && perRequest(item)) {
                e = encode(item); // values that change per request (ADR 0049, 0050) would only churn the cache
            } else if (e == null) {
                e = encode(item);
                if (encoded.size() >= cacheMax) {
                    encoded.clear();
                }
                encoded.put(item, e);
            }
            if (e.value() == null) {
                continue; // not encodable: warned when first seen
            }
            if (e.vendorId() == 0) {
                out.attribute(e.number(), e.value());
            } else if (vendors == null || vendors.contains(e.vendorId())) {
                out.vendorAttribute(e.vendorId(), e.number(), e.value());
            } else {
                AtomicLong count = filtered.get(nas); // absent only for a moment around a reload
                if (count != null) {
                    count.incrementAndGet();
                }
            }
        }
    }

    private static boolean perRequest(AttributeItem item) {
        return item.attribute().equalsIgnoreCase("Framed-IP-Address")
                || item.attribute().equalsIgnoreCase("Session-Timeout")
                || item.attribute().equalsIgnoreCase("Chargeable-User-Identity")
                || IpPools.IPV6_ATTRIBUTES.stream().anyMatch(item.attribute()::equalsIgnoreCase);
    }

    /** One reply item, encoded; {@code value == null} if it cannot be sent. Identity equality: a cached value. */
    static final class Encoded {
        private static final Encoded UNSENDABLE = new Encoded(0, 0, null);
        private final int vendorId;
        private final int number;
        private final byte[] value;

        Encoded(int vendorId, int number, byte[] value) {
            this.vendorId = vendorId;
            this.number = number;
            this.value = value;
        }

        int vendorId() {
            return vendorId;
        }

        int number() {
            return number;
        }

        byte[] value() {
            return value;
        }
    }

    private Encoded encode(AttributeItem item) {
        if (dictionary == null) {
            return Encoded.UNSENDABLE; // without a dictionary nothing can be encoded
        }
        String problem = AuthStores.replyProblem(dictionary, item);
        AttributeDef def = dictionary.find(item.attribute());
        if (problem != null || def == null) {
            once.warn("reply:" + item.attribute(), "{}: not sent", problem);
            return Encoded.UNSENDABLE;
        }
        byte[] value = AttributeText.encode(def, item.value());
        if (value.length > RadiusPacketEncoder.MAX_VALUE_LENGTH - (def.vendorId() == 0 ? 0 : 6)) {
            once.warn("reply-long:" + item.attribute(), "reply item {} is too long: not sent", item.attribute());
            return Encoded.UNSENDABLE;
        }
        return new Encoded(def.vendorId(), def.number(), value);
    }

    /** Takes the NAS entries with a vendor filter of a reloaded configuration; kept entries keep their counts. */
    void reload(Set<String> filteredNas) {
        filtered = counters(filteredNas, filtered);
    }

    private static Map<String, AtomicLong> counters(Set<String> nasNames, Map<String, AtomicLong> previous) {
        Map<String, AtomicLong> next = new HashMap<>();
        nasNames.forEach(nas -> next.put(nas, previous.getOrDefault(nas, new AtomicLong())));
        return Map.copyOf(next);
    }

    /** Vendor attributes left out of replies to {@code nas} because the NAS entry is of another vendor. */
    long filtered(String nas) {
        AtomicLong count = filtered.get(nas);
        return count == null ? 0 : count.get();
    }

    void writeMetrics(PrometheusWriter w, String radiusServer) {
        w.counter(
                "radiusward_gateway_access_reply_items_filtered_total",
                "Vendor attributes left out of Access-Accepts because the NAS entry is of another vendor");
        new TreeMap<>(filtered).forEach((nas, count) -> w.sample(count.get(), "gateway", radiusServer, "nas", nas));
    }
}
