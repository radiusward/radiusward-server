/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.collections.Object2ObjectHashMap;

/**
 * EAP conversations between their round trips (ADR 0026), keyed by the {@code State} the gateway sent: a fresh random
 * 16-byte token every round, so a {@code State} is good for exactly one response — taking a conversation out removes
 * it, and it goes back under a new token. Node-local: a conversation continues on the gateway that started it.
 *
 * <p>Shared by all workers: 16 stripes of Agrona maps, each behind its own lock. Bounded in count; when the table is
 * full, expired conversations are swept from every stripe before a new one is refused.
 */
final class EapConversations {

    /** One conversation between round trips. */
    static final class Conversation {
        final String nas;
        final String identity;
        EapMethod method;
        int identifier;
        int rounds;
        long expires;

        Conversation(String nas, String identity) {
            this.nas = nas;
            this.identity = identity;
        }
    }

    private record Key(long hi, long lo) {}

    /** One lock stripe: a map and the lock that guards it (an array of it needs no generic array). */
    private static final class Stripe {
        final Object2ObjectHashMap<Key, Conversation> map = new Object2ObjectHashMap<>();
    }

    private static final int STRIPES = 16;
    private final Stripe[] stripes = new Stripe[STRIPES];
    private final AtomicInteger size = new AtomicInteger();
    private final int capacity;
    private final SecureRandom random = new SecureRandom();

    EapConversations(int capacity) {
        this.capacity = capacity;
        for (int i = 0; i < STRIPES; i++) {
            stripes[i] = new Stripe();
        }
    }

    /**
     * Keeps {@code c} until its peer answers; returns the 16-byte State to send, or {@code null} when the table is
     * full (the request is then not answered).
     */
    byte[] put(Conversation c, long now) {
        byte[] state = new byte[16];
        random.nextBytes(state);
        Key key = key(state);
        if (size.get() >= capacity) {
            for (Stripe s : stripes) {
                synchronized (s) {
                    sweep(s.map, now);
                }
            }
            if (size.get() >= capacity) {
                return null;
            }
        }
        Stripe stripe = stripes[stripe(key)];
        synchronized (stripe) {
            stripe.map.put(key, c);
            size.incrementAndGet();
        }
        return state;
    }

    /** Takes the conversation of {@code state} out, if it exists, is not expired and belongs to {@code nas}. */
    Conversation take(byte[] state, String nas, long now) {
        if (state.length != 16) {
            return null;
        }
        Key key = key(state);
        Stripe stripe = stripes[stripe(key)];
        Conversation c;
        synchronized (stripe) {
            c = stripe.map.remove(key);
            if (c != null) {
                size.decrementAndGet();
            }
        }
        if (c == null || c.expires - now <= 0 || !c.nas.equals(nas)) {
            return null; // unknown, used, expired, or another NAS presenting it
        }
        return c;
    }

    int size() {
        return size.get();
    }

    private void sweep(Object2ObjectHashMap<Key, Conversation> stripe, long now) {
        var it = stripe.values().iterator();
        while (it.hasNext()) {
            if (it.next().expires - now <= 0) {
                it.remove();
                size.decrementAndGet();
            }
        }
    }

    private static Key key(byte[] state) {
        ByteBuffer b = ByteBuffer.wrap(state);
        return new Key(b.getLong(), b.getLong());
    }

    private static int stripe(Key key) {
        return (int) ((key.hi() ^ key.lo()) >>> 60) & (STRIPES - 1);
    }
}
