/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.radius.codec.RadiusPacket;

/**
 * Addresses from IP pools for an Accept (ADR 0050, ADR 0059): the pools a user's {@code Pool-Name} names, unless the
 * reply already carries an address or prefix of that kind.
 */
final class AddressAssignment {

    private static final int CALLING_STATION_ID = 31;

    private final OnceLogger once;

    AddressAssignment(OnceLogger once) {
        this.once = once;
    }

    private volatile IpPools pools;

    void pools(IpPools pools) {
        this.pools = pools;
    }

    /**
     * A {@code Framed-IP-Address} from the pool named by the user's (else a group's) {@code Pool-Name}, unless the
     * reply already has one. An empty pool rejects (or accepts without an address, per pool); a pool that cannot be
     * reached leaves the request unanswered.
     */
    int assign(AccessContext context, RadiusPacket request, String user, StoreAccessHandler.Authorization a) {
        for (AttributeItem item : a.restrictions()) {
            if (!item.attribute().equalsIgnoreCase("Pool-Name")) {
                continue;
            }
            for (String name : item.value().split(",")) { // e.g. an IPv4 pool and an IPv6 one (ADR 0059)
                int decision = assign(context, request, user, a, name.trim());
                if (decision != AccessHandler.ACCEPT) {
                    return decision;
                }
            }
        }
        return AccessHandler.ACCEPT;
    }

    private int assign(
            AccessContext context, RadiusPacket request, String user, StoreAccessHandler.Authorization a, String name) {
        IpPools p = pools;
        IpPools.Pool pool = p == null ? null : p.pool(name);
        if (pool == null) {
            once.warn("pool:" + name, "Pool-Name {}: no such pool in auth.pools, the user is rejected", name);
            StoreAccessHandler.because(context, "no such pool: ", name);
            return AccessHandler.REJECT;
        }
        if (a.reply().stream().anyMatch(r -> r.attribute().equalsIgnoreCase(pool.attribute()))) {
            return AccessHandler.ACCEPT; // the user's own address or prefix
        }
        int station = request.findAttribute(CALLING_STATION_ID);
        String device = station < 0
                ? user
                : request.buffer()
                        .getStringWithoutLengthUtf8(
                                station + 2, (request.buffer().getByte(station + 1) & 0xFF) - 2);
        String address;
        try {
            address = p.allocate(pool, user, device);
        } catch (Exception e) {
            once.warn(
                    "pool-unavailable:" + pool.name(),
                    "IP pool {} unavailable, requests are not answered: {}",
                    pool.name(),
                    e.toString());
            StoreAccessHandler.because(context, "IP pool unavailable: ", pool.name());
            return AccessHandler.DROP;
        }
        if (address == null) {
            once.warn("pool-empty:" + pool.name(), "IP pool {} has no free address", pool.name());
            StoreAccessHandler.because(context, "IP pool has no free address: ", pool.name());
            return pool.exhausted() ? AccessHandler.ACCEPT : AccessHandler.REJECT;
        }
        StoreAccessHandler.note(context, "address from pool " + pool.name() + ": ", address);
        a.reply().add(new AttributeItem(pool.attribute(), "=", address));
        return AccessHandler.ACCEPT;
    }
}
