/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.common.config.Config;
import io.radiusward.radius.dictionary.Dictionary;
import java.time.ZoneId;

/**
 * The settings of the store handler beyond the stores: replaced as a whole when the configuration is reloaded (ADR
 * 0054). Each request takes them once ({@link AuthRequest#begin}) and keeps them to the end, so a reload never gives
 * it a mix of old and new.
 *
 * @param counters usage counters ({@code auth.counters}, ADR 0049); {@code null} without
 * @param zone the zone of Login-Time, counter periods and dates without one ({@code auth.time.zone})
 * @param pools IP pools ({@code auth.pools}, ADR 0050); {@code null} without
 * @param totp the TOTP second factor ({@code auth.totp.*}, ADR 0053)
 * @param cui Chargeable-User-Identity ({@code auth.cui.*}, ADR 0056); {@code null} without
 * @param rules the rules file ({@code auth.rules}, ADR 0051); {@code null} without
 */
record AccessPolicies(UsageCounters counters, ZoneId zone, IpPools pools, Totp totp, Cui cui, RulesFile rules) {

    /** None of them: no counters, pools, CUI or rules, TOTP's defaults, the system zone. */
    static final AccessPolicies NONE = new AccessPolicies(null, ZoneId.systemDefault(), null, Totp.DEFAULT, null, null);

    /** The settings of {@code config}; the dictionary checks the attributes the rules name. */
    static AccessPolicies from(Config config, Dictionary dictionary) {
        return new AccessPolicies(
                UsageCounters.from(config),
                UsageCounters.zone(config),
                IpPools.from(config),
                Totp.from(config),
                Cui.from(config),
                RulesFile.from(config, name -> dictionary.find(name) != null));
    }
}
