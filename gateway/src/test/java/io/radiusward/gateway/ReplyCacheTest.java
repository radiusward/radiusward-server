/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.Duration;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class ReplyCacheTest {

    private final UnsafeBuffer reply = new UnsafeBuffer(new byte[8192]);
    private final UnsafeBuffer out = new UnsafeBuffer(new byte[8192]);

    @Test
    void inFlightThenCachedUntilExpiry() {
        ReplyCache cache = new ReplyCache(16);
        assertThat(cache.lookup(7, 0)).isEqualTo(ReplyCache.MISSING);
        cache.markInFlight(7);
        assertThat(cache.lookup(7, 0)).isEqualTo(ReplyCache.IN_FLIGHT);
        reply.putByte(0, (byte) 2);
        cache.put(7, reply, 0, 38, 100);
        int entry = cache.lookup(7, 99);
        assertThat(entry).isNotNegative();
        assertThat(cache.copy(entry, out, 0)).isEqualTo(38);
        assertThat(out.getByte(0)).isEqualTo((byte) 2);
        assertThat(cache.size()).isEqualTo(1);
        assertThat(cache.lookup(7, 100)).as("expired").isEqualTo(ReplyCache.MISSING);
        assertThat(cache.size()).isZero();
    }

    @Test
    void theOldestEntryIsReplacedWhenFull() {
        ReplyCache cache = new ReplyCache(16);
        for (long key = 1; key <= 17; key++) {
            cache.put(key, reply, 0, 20, Long.MAX_VALUE);
        }
        assertThat(cache.lookup(1, 0)).isEqualTo(ReplyCache.MISSING);
        assertThat(cache.lookup(2, 0)).isNotNegative();
        assertThat(cache.lookup(17, 0)).isNotNegative();
        assertThat(cache.size()).isEqualTo(16);
    }

    @Test
    void largeRepliesUpToTheRadiusMaximumAreKeptInTheirOwnRing() {
        ReplyCache cache = new ReplyCache(16);
        reply.setMemory(0, ReplyCache.MAX_LARGE_REPLY, (byte) 7);
        cache.put(1, reply, 0, ReplyCache.MAX_LARGE_REPLY, Long.MAX_VALUE);
        int entry = cache.lookup(1, 0);
        assertThat(entry).isNotNegative();
        assertThat(cache.copy(entry, out, 0)).isEqualTo(ReplyCache.MAX_LARGE_REPLY);
        assertThat(out.getByte(ReplyCache.MAX_LARGE_REPLY - 1)).isEqualTo((byte) 7);
        for (long key = 2; key <= 16; key++) {
            cache.put(key, reply, 0, 20, Long.MAX_VALUE); // small replies do not push large ones out
        }
        assertThat(cache.lookup(1, 0)).isNotNegative();
        for (long key = 100; key < 116; key++) {
            cache.put(key, reply, 0, ReplyCache.MAX_REPLY + 1, Long.MAX_VALUE);
        }
        assertThat(cache.lookup(1, 0)).as("the oldest large reply replaced").isEqualTo(ReplyCache.MISSING);
        assertThat(cache.lookup(115, 0)).isNotNegative();
        assertThat(cache.lookup(16, 0)).isNotNegative();
        assertThat(cache.size()).isEqualTo(31);
    }

    @Test
    void oversizedRepliesAndUnansweredRequestsOnlyClearTheMark() {
        ReplyCache cache = new ReplyCache(16);
        cache.markInFlight(1);
        cache.put(1, reply, 0, ReplyCache.MAX_LARGE_REPLY + 1, Long.MAX_VALUE);
        assertThat(cache.lookup(1, 0)).isEqualTo(ReplyCache.MISSING);
        cache.markInFlight(2);
        cache.clearInFlight(2);
        assertThat(cache.lookup(2, 0)).isEqualTo(ReplyCache.MISSING);
        cache.put(3, reply, 0, 20, Long.MAX_VALUE);
        cache.clearInFlight(3);
        assertThat(cache.lookup(3, 0)).as("a reply is not cleared as in flight").isNotNegative();
    }

    @Test
    void authConfigDefaultsAndLimits() {
        AuthConfig c = AuthConfig.from(Config.of(Map.of()));
        assertThat(c.enabled()).isFalse();
        assertThat(c.port()).isEqualTo(1812);
        assertThat(c.workers()).isEqualTo(4);
        assertThat(c.pending()).isEqualTo(256);
        assertThat(c.replyCacheTtl()).isEqualTo(Duration.ofSeconds(10));
        AuthConfig on = AuthConfig.from(Config.of(
                Map.of("gateway.auth.enabled", "true", "gateway.auth.workers", "16", "gateway.auth.pending", "1024")));
        assertThat(on.enabled()).isTrue();
        assertThat(on.workers()).isEqualTo(16);
        for (Map<String, String> bad : java.util.List.of(
                Map.of("gateway.auth.workers", "0"),
                Map.of("gateway.auth.pending", "100"),
                Map.of("gateway.auth.reply.cache.entries", "8"),
                Map.of("gateway.auth.reply.cache.ttl", "0s"),
                Map.of("gateway.auth.port", "70000"))) {
            assertThatThrownBy(() -> AuthConfig.from(Config.of(bad))).isInstanceOf(ConfigException.class);
        }
    }
}
