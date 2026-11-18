/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/** RFC 7585 look-ups kept per realm for their TTL, without the proxy ever waiting for DNS. */
class DiscoveredRealmsTest {

    private static final ProxyConfig.Discovery SETTINGS = new ProxyConfig.Discovery(
            "127.0.0.1", Duration.ofSeconds(60), Duration.ofSeconds(5), null, null, null, new byte[0]);

    private final long[] now = {1_000};
    private final List<String> asked = new ArrayList<>();
    private final List<Runnable> queued = new ArrayList<>();
    private List<RealmDiscovery.Target> answer = List.of(new RealmDiscovery.Target("radsec.partner.example", 2083));
    private boolean down;

    /** Runs look-ups when the test says so, as the discovery thread would later. */
    private final AbstractExecutorService later = new AbstractExecutorService() {
        @Override
        public void execute(Runnable command) {
            queued.add(command);
        }

        @Override
        public void shutdown() {}

        @Override
        public List<Runnable> shutdownNow() {
            return List.of();
        }

        @Override
        public boolean isShutdown() {
            return false;
        }

        @Override
        public boolean isTerminated() {
            return false;
        }

        @Override
        public boolean awaitTermination(long timeout, TimeUnit unit) {
            return true;
        }
    };

    private final DiscoveredRealms.Resolver dns = new DiscoveredRealms.Resolver() {
        @Override
        public List<RealmDiscovery.Target> lookup(String realm) throws Exception {
            asked.add(realm);
            if (down) {
                throw new javax.naming.NamingException("no DNS");
            }
            return answer;
        }

        @Override
        public InetAddress address(String host) throws Exception {
            return InetAddress.getByAddress(host, new byte[] {10, 0, 0, 1});
        }
    };

    private final DiscoveredRealms realms = new DiscoveredRealms(SETTINGS, dns, later, () -> now[0]);
    private final List<String> created = new ArrayList<>();
    private final DiscoveredRealms.Homes homes = (target, address) -> {
        created.add(target.host() + ":" + target.port() + "@" + address.getHostAddress());
        return 7;
    };

    private void runLookups() {
        List<Runnable> run = new ArrayList<>(queued);
        queued.clear();
        run.forEach(Runnable::run);
    }

    @Test
    void aRealmIsLookedUpOnceAndKeptForItsTtl() {
        assertThat(realms.pool("partner.example", now[0], homes))
                .as("being looked up")
                .isNull();
        assertThat(realms.pool("partner.example", now[0], homes))
                .as("still: one look-up at a time")
                .isNull();
        assertThat(queued).hasSize(1);
        runLookups();
        assertThat(realms.pool("partner.example", now[0], homes)).containsExactly(7);
        assertThat(created).containsExactly("radsec.partner.example:2083@10.0.0.1");
        now[0] += Duration.ofSeconds(59).toNanos();
        assertThat(realms.pool("partner.example", now[0], homes)).containsExactly(7);
        assertThat(asked).as("kept for the TTL").containsExactly("partner.example");
        assertThat(created).as("the pool is built once").hasSize(1);

        now[0] += Duration.ofSeconds(2).toNanos();
        assertThat(realms.pool("partner.example", now[0], homes))
                .as("expired: looked up again")
                .isNull();
        runLookups();
        assertThat(asked).hasSize(2);
    }

    @Test
    void noAnswerAndFailuresAreKeptForTheNegativeTtl() {
        answer = List.of();
        realms.pool("empty.example", now[0], homes);
        down = true;
        realms.pool("broken.example", now[0], homes);
        runLookups();
        assertThat(realms.pool("empty.example", now[0], homes))
                .as("no servers published")
                .isEmpty();
        assertThat(realms.pool("broken.example", now[0], homes))
                .as("DNS failed")
                .isEmpty();
        now[0] += Duration.ofSeconds(4).toNanos();
        assertThat(realms.pool("broken.example", now[0], homes)).isEmpty();
        assertThat(asked).hasSize(2);
        now[0] += Duration.ofSeconds(2).toNanos();
        assertThat(realms.pool("broken.example", now[0], homes))
                .as("the negative TTL is over")
                .isNull();
        assertThat(queued).hasSize(1);
    }
}
