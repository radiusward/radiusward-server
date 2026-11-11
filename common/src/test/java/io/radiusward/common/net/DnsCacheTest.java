/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Security;
import org.junit.jupiter.api.Test;

class DnsCacheTest {

    @Test
    void shortCacheUnlessTheOperatorChoseOne() {
        String ttl = Security.getProperty(DnsCache.TTL);
        String negative = Security.getProperty(DnsCache.NEGATIVE_TTL);
        try {
            System.setProperty("sun.net.inetaddr.ttl", "30");
            assertThat(DnsCache.shortLived()).as("system property set").isFalse();
            System.clearProperty("sun.net.inetaddr.ttl");

            if (ttl == null) {
                assertThat(DnsCache.shortLived()).isTrue();
                assertThat(Security.getProperty(DnsCache.TTL)).isEqualTo("1");
                assertThat(Security.getProperty(DnsCache.NEGATIVE_TTL)).isEqualTo("0");
            }
            assertThat(DnsCache.shortLived()).as("now set: left alone").isFalse();
        } finally {
            System.clearProperty("sun.net.inetaddr.ttl");
            Security.setProperty(DnsCache.TTL, ttl == null ? "30" : ttl);
            Security.setProperty(DnsCache.NEGATIVE_TTL, negative == null ? "10" : negative);
        }
    }
}
