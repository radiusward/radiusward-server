/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** NAS entries looked up on demand (ADR 0046), with a fake source; SQL through a gateway: {@code DynamicClientsIT}. */
class DynamicClientsTest {

    static final int NET = 0x0A010000; // 10.1.0.0/16
    private DynamicClients clients;

    @AfterEach
    void close() {
        if (clients != null) {
            clients.close();
        }
    }

    private final AtomicInteger asked = new AtomicInteger();
    private final AtomicBoolean failing = new AtomicBoolean();

    private DynamicClients.Source source() {
        return address -> {
            asked.incrementAndGet();
            if (failing.get()) {
                throw new IllegalStateException("database down");
            }
            String ip = address.getHostAddress();
            return ip.endsWith(".9")
                    ? null
                    : new DynamicClients.Row(ip, "ap-" + ip, "s3cret".getBytes(StandardCharsets.US_ASCII), "Ruckus");
        };
    }

    private NasClient await(int address) throws InterruptedException {
        for (int i = 0; i < 200; i++) {
            NasClient c = clients.find(address, System.currentTimeMillis());
            if (c != null) {
                return c;
            }
            Thread.sleep(10);
        }
        return null;
    }

    @Test
    void anUnknownAddressIsLookedUpOnceThenServedFromTheTable() throws Exception {
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}), source(), Duration.ofHours(1), Duration.ofMinutes(1), 100);
        int address = NET + 5;
        assertThat(clients.find(address, System.currentTimeMillis()))
                .as("the first packet is dropped")
                .isNull();
        NasClient c = await(address);
        assertThat(c).isNotNull();
        assertThat(c.name()).isEqualTo("dynamic:ap-10.1.0.5");
        assertThat(new String(c.secret(), StandardCharsets.US_ASCII)).isEqualTo("s3cret");
        assertThat(c.vendor()).isEqualTo("ruckus");
        assertThat(c.id()).as("the same on every gateway").isEqualTo(NasRegistry.fnv1a("dynamic:10.1.0.5"));
        for (int i = 0; i < 10; i++) {
            clients.find(address, System.currentTimeMillis());
        }
        assertThat(asked.get()).isEqualTo(1);
        assertThat(clients.find(0x0A020005, System.currentTimeMillis()))
                .as("outside the networks")
                .isNull();
        Thread.sleep(50);
        assertThat(asked.get()).isEqualTo(1);
        assertThat(clients.get(DynamicClients.Counter.FOUND)).isEqualTo(1);
        assertThat(clients.size()).isEqualTo(1);
    }

    @Test
    void unknownAddressesAreNotAskedForAgainBeforeTheNegativeTtl() throws Exception {
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}), source(), Duration.ofHours(1), Duration.ofMillis(300), 100);
        int unknown = NET + 9;
        clients.find(unknown, System.currentTimeMillis());
        Thread.sleep(150);
        for (int i = 0; i < 5; i++) {
            assertThat(clients.find(unknown, System.currentTimeMillis())).isNull();
        }
        assertThat(asked.get()).as("one lookup within the negative TTL").isEqualTo(1);
        Thread.sleep(300);
        clients.find(unknown, System.currentTimeMillis());
        Thread.sleep(150);
        assertThat(asked.get()).as("asked again after it").isEqualTo(2);
        assertThat(clients.get(DynamicClients.Counter.NOT_FOUND)).isEqualTo(2);
    }

    @Test
    void entriesExpireAndFailuresAreRetried() throws Exception {
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}), source(), Duration.ofMillis(200), Duration.ofMinutes(1), 100);
        int address = NET + 7;
        clients.find(address, System.currentTimeMillis());
        assertThat(await(address)).isNotNull();
        assertThat(clients.find(address, System.currentTimeMillis() + 1_000))
                .as("past its lifetime")
                .isNull();
        LocalWait.until(() -> asked.get() == 2);
        failing.set(true);
        clients = restart(Duration.ofHours(1));
        clients.find(NET + 8, System.currentTimeMillis());
        LocalWait.until(() -> clients.get(DynamicClients.Counter.FAILED) == 1);
        failing.set(false);
        assertThat(await(NET + 8)).as("asked again with the next packet").isNotNull();
    }

    private DynamicClients restart(Duration lifetime) {
        clients.close();
        return new DynamicClients(List.of(new int[] {NET, 16}), source(), lifetime, Duration.ofMinutes(1), 1);
    }

    @Test
    void theTableIsBounded() throws Exception {
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}), source(), Duration.ofHours(1), Duration.ofMinutes(1), 1);
        clients.find(NET + 1, System.currentTimeMillis());
        assertThat(await(NET + 1)).isNotNull();
        clients.find(NET + 2, System.currentTimeMillis());
        LocalWait.until(() -> asked.get() == 2);
        Thread.sleep(50);
        assertThat(clients.find(NET + 2, System.currentTimeMillis()))
                .as("nas.dynamic.max reached")
                .isNull();
        assertThat(clients.size()).isEqualTo(1);
    }

    @Test
    void configuration() {
        assertThat(DynamicClients.from(Config.of(Map.of()))).isNull();
        assertThatThrownBy(() -> DynamicClients.from(Config.of(Map.of("nas.dynamic.enabled", "true"))))
                .hasMessageContaining("nas.dynamic.networks");
        assertThatThrownBy(() -> DynamicClients.from(Config.of(Map.of(
                        "nas.dynamic.enabled",
                        "true",
                        "nas.dynamic.networks",
                        "10.0.0.0/4",
                        "nas.dynamic.sql.url",
                        "x"))))
                .hasMessageContaining("prefix 8 to 32");
        DynamicClients d = DynamicClients.from(Config.of(Map.of(
                "nas.dynamic.enabled", "true",
                "nas.dynamic.networks", "10.1.0.0/16, 192.0.2.7",
                "nas.dynamic.sql.url", "jdbc:none:test")));
        try {
            assertThat(d).isNotNull();
        } finally {
            d.close();
        }
        NasRegistry registry = NasRegistry.from(Config.of(Map.of(
                "nas.dynamic.enabled", "true",
                "nas.dynamic.networks", "10.1.0.0/16",
                "nas.dynamic.sql.url", "jdbc:none:test")));
        try {
            assertThat(registry.clients()).as("no configured entry is needed").isEmpty();
            assertThat(registry.dynamic()).isNotNull();
        } finally {
            registry.dynamic().close();
        }
        assertThat(NasRegistry.inet(0x0A010005)).isEqualTo(addr());
    }

    private static InetAddress addr() {
        try {
            return InetAddress.getByName("10.1.0.5");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static final class LocalWait {
        static void until(java.util.function.BooleanSupplier condition) throws InterruptedException {
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (!condition.getAsBoolean()) {
                if (System.nanoTime() > deadline) {
                    throw new AssertionError("condition not met within 5 s");
                }
                Thread.sleep(10);
            }
        }
    }
}
