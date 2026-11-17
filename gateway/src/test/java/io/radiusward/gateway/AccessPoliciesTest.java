/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.ZoneId;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AccessPoliciesTest {

    @Test
    void aConfigurationWithoutThemHasNone() {
        AccessPolicies none = AccessPolicies.from(Config.of(Map.of()), StoreAccessHandlerTest.DICTIONARY);
        assertThat(none.counters()).isNull();
        assertThat(none.pools()).isNull();
        assertThat(none.cui()).isNull();
        assertThat(none.rules()).isNull();
        assertThat(none.zone()).isEqualTo(ZoneId.systemDefault());
        assertThat(none.totp()).isEqualTo(Totp.DEFAULT);
        assertThat(AccessPolicies.NONE).isEqualTo(none);
    }

    @Test
    void theyAreReadFromTheConfiguration() {
        AccessPolicies set = AccessPolicies.from(
                Config.of(Map.of(
                        "auth.time.zone", "Europe/Kyiv",
                        "auth.cui.key", "a-key-of-sixteen-chars")),
                StoreAccessHandlerTest.DICTIONARY);
        assertThat(set.zone()).isEqualTo(ZoneId.of("Europe/Kyiv"));
        assertThat(set.cui()).isNotNull();
        assertThatThrownBy(() -> AccessPolicies.from(
                        Config.of(Map.of("auth.time.zone", "Nowhere/Else")), StoreAccessHandlerTest.DICTIONARY))
                .isInstanceOf(ConfigException.class);
    }
}
