/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.UserRecord;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.util.ArrayList;

/**
 * What decides after the credential was checked whether an authorized user gets in, and with what: Simultaneous-Use
 * (ADR 0023), the restrictions of the user and its groups (Expiration, Login-Time, usage counters; ADR 0049), an
 * address from a pool (ADR 0050), the rules ({@code auth.rules}, ADR 0051), and Chargeable-User-Identity (ADR 0056).
 * Each may add to the reply items.
 */
final class Admission {

    private final Dictionary dictionary;
    private final CheckItems checkItems;
    private final Restrictions restrictions;
    private final AddressAssignment addresses;
    private volatile RulesFile rules;
    private volatile Cui cui;

    Admission(Dictionary dictionary, CheckItems checkItems, Restrictions restrictions, OnceLogger once) {
        this.dictionary = dictionary;
        this.checkItems = checkItems;
        this.restrictions = restrictions;
        this.addresses = new AddressAssignment(once);
    }

    void pools(IpPools pools) {
        addresses.pools(pools);
    }

    void rules(RulesFile rules) {
        this.rules = rules;
    }

    void cui(Cui cui) {
        this.cui = cui;
    }

    /**
     * {@link AccessHandler#ACCEPT} with the reply items of {@code a} completed, {@link AccessHandler#REJECT} or
     * {@link AccessHandler#DROP} (a session or pool look-up that cannot be answered now).
     */
    int admit(AccessContext context, UserDirectory.Found found, UserDirectory.Authorization a) {
        RadiusPacket request = context.request();
        if (a.limit() != null) {
            int decision = restrictions.limit(context, request, found.store(), a.limit());
            if (decision != AccessHandler.ACCEPT) {
                StoreAccessHandler.because(context, "Simultaneous-Use not granted: ", a.limit());
                return decision;
            }
        }
        int restricted = restrictions.restrict(context, found.user().userName(), a);
        if (restricted != AccessHandler.ACCEPT) {
            return restricted;
        }
        int pooled = addresses.assign(context, request, found.user().userName(), a);
        if (pooled != AccessHandler.ACCEPT) {
            return pooled;
        }
        RulesFile r = rules;
        if (r != null && !r.current().apply(ruleRequest(request, found.user()), a.reply())) {
            StoreAccessHandler.because(context, "rejected by a rule of ", "auth.rules");
            return AccessHandler.REJECT;
        }
        Cui c = cui;
        if (c != null) {
            c.apply(request, found.user().userName(), a.reply()); // ADR 0056
        }
        return AccessHandler.ACCEPT;
    }

    private Rules.Request ruleRequest(RadiusPacket request, UserRecord user) {
        return new Rules.Request() {
            @Override
            public String value(String attribute) {
                AttributeDef def = dictionary.find(attribute);
                if (def == null || def.vendorId() != 0) {
                    return null;
                }
                int at = request.findAttribute(def.number());
                return at < 0
                        ? null
                        : AttributeText.decode(
                                def, request.buffer(), at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
            }

            @Override
            public boolean inGroup(String group) {
                for (UserRecord.Group g : user.groups()) {
                    if (g.name().equalsIgnoreCase(group)
                            && checkItems.checks(g.check(), request, new ArrayList<>()) != null) {
                        return true;
                    }
                }
                return false;
            }
        };
    }
}
