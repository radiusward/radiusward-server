/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

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

/** NAS entries looked up on demand (ADR 0046), with a fake source; SQL through a RADIUS server: {@code DynamicClientsIT}. */
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
        assertThat(c.id()).as("the same on every RADIUS server").isEqualTo(NasConfig.fnv1a("dynamic:10.1.0.5"));
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

    @Test
    void invalidConfigurationIsRefused() {
        assertThatThrownBy(() -> DynamicClients.from(Config.of(Map.of(
                        "nas.dynamic.enabled", "true",
                        "nas.dynamic.networks", "10.0.0.0/33",
                        "nas.dynamic.sql.url", "x"))))
                .hasMessageContaining("prefix 8 to 32, got 10.0.0.0/33");
        assertThatThrownBy(() -> DynamicClients.from(Config.of(Map.of(
                        "nas.dynamic.enabled", "true",
                        "nas.dynamic.networks", " , ",
                        "nas.dynamic.sql.url", "x"))))
                .hasMessageContaining("nas.dynamic.networks: required");
        assertThatThrownBy(() -> DynamicClients.from(Config.of(Map.of(
                        "nas.dynamic.enabled", "true",
                        "nas.dynamic.networks", "10.1.0.0/16",
                        "nas.dynamic.sql.url", "x",
                        "nas.dynamic.max", "0"))))
                .hasMessageContaining("nas.dynamic.max: at least 1");
    }

    @Test
    void rowsWithoutSecretAreNotFoundAndMissingNamesAndTypesHaveDefaults() throws Exception {
        clients = new DynamicClients(
                List.of(new int[] {0, 0}), // every address
                address -> switch (address.getHostAddress()) {
                    case "10.1.0.1" -> new DynamicClients.Row("10.1.0.1", null, null, "cisco");
                    case "10.1.0.2" -> new DynamicClients.Row("10.1.0.2", "ap", new byte[0], "cisco");
                    case "10.1.0.3" ->
                        new DynamicClients.Row("10.1.0.3", null, "s".getBytes(StandardCharsets.US_ASCII), null);
                    default -> new DynamicClients.Row("x", " ", "s".getBytes(StandardCharsets.US_ASCII), " ");
                },
                Duration.ofHours(1),
                Duration.ofHours(1),
                100);
        clients.find(NET + 1, System.currentTimeMillis());
        clients.find(NET + 2, System.currentTimeMillis());
        LocalWait.until(() -> clients.get(DynamicClients.Counter.NOT_FOUND) == 2);
        assertThat(clients.size())
                .as("no secret, or an empty one: not an entry")
                .isZero();

        NasClient unnamed = await(NET + 3);
        assertThat(unnamed.name()).as("named after its address").isEqualTo("dynamic:10.1.0.3");
        assertThat(unnamed.vendor()).isEqualTo("default");
        NasClient blank = await(0xC0000207); // 192.0.2.7: a network of prefix 0 holds every address
        assertThat(blank.name()).isEqualTo("dynamic:192.0.2.7");
        assertThat(blank.vendor()).isEqualTo("default");
    }

    @Test
    void aNasFoundAfterItWasMissingIsNoLongerMissing() throws Exception {
        AtomicBoolean known = new AtomicBoolean();
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}),
                address -> {
                    asked.incrementAndGet();
                    return known.get()
                            ? new DynamicClients.Row("10.1.0.4", "ap", "s".getBytes(StandardCharsets.US_ASCII), "cisco")
                            : null;
                },
                Duration.ofMinutes(1),
                Duration.ofHours(1),
                100);
        int address = NET + 4;
        long start = System.currentTimeMillis();
        clients.find(address, start);
        LocalWait.until(() -> clients.get(DynamicClients.Counter.NOT_FOUND) == 1);
        assertThat(clients.find(address, start + 1_000))
                .as("missing for the negative TTL")
                .isNull();
        known.set(true);
        long later = start + 2 * 3_600_000L; // past the negative TTL
        askUntil(address, later, 2);
        LocalWait.until(() -> clients.get(DynamicClients.Counter.FOUND) == 1);

        // half an hour on, the entry's lifetime is over but the old negative TTL would not be: asked again
        askUntil(address, start + 1_800_000L, 3);
        assertThat(asked.get()).isEqualTo(3);
    }

    /** Packets from {@code address} until the source was asked {@code times}: one is ignored while still pending. */
    private void askUntil(int address, long now, int times) throws InterruptedException {
        LocalWait.until(() -> asked.get() >= times || clients.find(address, now) != null);
    }

    @Test
    void lookupsBeyondTheQueueAreCountedAndAskedForWithTheNextPacket() throws Exception {
        java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}),
                address -> {
                    entered.countDown();
                    release.await();
                    return null;
                },
                Duration.ofHours(1),
                Duration.ofHours(1),
                100);
        long now = System.currentTimeMillis();
        clients.find(NET, now);
        assertThat(entered.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue(); // the thread is busy
        for (int i = 1; i <= 1024; i++) {
            clients.find(NET + i, now); // the queue holds 1024
        }
        assertThat(clients.get(DynamicClients.Counter.QUEUE_FULL)).isZero();
        clients.find(NET + 1025, now);
        clients.find(NET + 1025, now);
        assertThat(clients.get(DynamicClients.Counter.QUEUE_FULL))
                .as("not pending: each packet tries again")
                .isEqualTo(2);
        clients.find(NET + 1, now);
        assertThat(clients.get(DynamicClients.Counter.QUEUE_FULL))
                .as("already queued")
                .isEqualTo(2);
        release.countDown();
    }

    @Test
    void aFullTableMakesRoomByDroppingExpiredEntriesAndMisses() throws Exception {
        clients = new DynamicClients(List.of(new int[] {NET, 16}), source(), Duration.ZERO, Duration.ZERO, 1);
        clients.find(NET + 9, System.currentTimeMillis()); // not in the source
        LocalWait.until(() -> clients.get(DynamicClients.Counter.NOT_FOUND) == 1);
        clients.find(NET + 1, System.currentTimeMillis());
        LocalWait.until(() -> clients.get(DynamicClients.Counter.FOUND) == 1);
        assertThat(clients.size()).isEqualTo(1);
        clients.find(NET + 2, System.currentTimeMillis());
        LocalWait.until(() -> clients.get(DynamicClients.Counter.FOUND) == 2);
        assertThat(clients.get(DynamicClients.Counter.EXPIRED))
                .as("the first entry made room")
                .isEqualTo(1);
        assertThat(clients.size()).isEqualTo(1);
        assertThat(clients.find(NET + 2, System.currentTimeMillis() - 1_000))
                .as("the new entry, within its lifetime")
                .isNotNull();
    }

    @Test
    void aFullTableDropsOnlyWhatIsPastItsTime() throws Exception {
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}), source(), Duration.ofMillis(300), Duration.ofMillis(300), 2);
        clients.find(NET + 1, System.currentTimeMillis());
        clients.find(NET + 9, System.currentTimeMillis()); // not in the source
        LocalWait.until(() ->
                clients.get(DynamicClients.Counter.FOUND) == 1 && clients.get(DynamicClients.Counter.NOT_FOUND) == 1);
        Thread.sleep(400); // the first entry and miss are past their time
        clients.find(NET + 2, System.currentTimeMillis());
        clients.find(0x0A010109, System.currentTimeMillis()); // 10.1.1.9: not in the source either
        LocalWait.until(() ->
                clients.get(DynamicClients.Counter.FOUND) == 2 && clients.get(DynamicClients.Counter.NOT_FOUND) == 2);
        assertThat(clients.size()).isEqualTo(2);

        clients.find(NET + 3, System.currentTimeMillis()); // full: makes room
        LocalWait.until(() -> clients.get(DynamicClients.Counter.FOUND) == 3);
        assertThat(clients.get(DynamicClients.Counter.EXPIRED)).isEqualTo(1);
        assertThat(clients.size()).isEqualTo(2);
        assertThat(clients.find(NET + 2, System.currentTimeMillis()))
                .as("the younger entry is kept")
                .isNotNull();
        int before = asked.get();
        clients.find(0x0A010109, System.currentTimeMillis());
        clients.find(NET + 9, System.currentTimeMillis());
        LocalWait.until(() -> asked.get() == before + 1);
        Thread.sleep(50);
        assertThat(asked.get())
                .as("the old miss is asked for again, the young one is still kept")
                .isEqualTo(before + 1);
    }

    @Test
    void anEntryLookedUpAgainReplacesItselfInAFullTable() throws Exception {
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}), source(), Duration.ofMinutes(1), Duration.ofMinutes(1), 1);
        clients.find(NET + 1, System.currentTimeMillis());
        LocalWait.until(() -> clients.get(DynamicClients.Counter.FOUND) == 1);
        long later = System.currentTimeMillis() + 120_000; // past its lifetime
        LocalWait.until(() -> clients.get(DynamicClients.Counter.FOUND) == 2 || clients.find(NET + 1, later) != null);
        assertThat(clients.size()).isEqualTo(1);
        assertThat(clients.get(DynamicClients.Counter.EXPIRED))
                .as("nothing had to make room")
                .isZero();
        assertThat(clients.find(NET + 1, System.currentTimeMillis()))
                .as("renewed")
                .isNotNull();
    }

    @Test
    void entriesAndMissesExpireWhileTheLookUpThreadIsIdle() throws Exception {
        clients = new DynamicClients(
                List.of(new int[] {NET, 16}), source(), Duration.ofMillis(100), Duration.ofMillis(100), 100);
        clients.find(NET + 1, System.currentTimeMillis());
        clients.find(NET + 9, System.currentTimeMillis());
        LocalWait.until(() ->
                clients.get(DynamicClients.Counter.FOUND) == 1 && clients.get(DynamicClients.Counter.NOT_FOUND) == 1);
        LocalWait.until(() -> clients.size() == 0); // after the 1 s poll finds nothing to look up
        assertThat(clients.get(DynamicClients.Counter.EXPIRED)).isEqualTo(1);
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

    @Test
    void closingInterruptsTheWaitingLookUpThread() throws Exception {
        DynamicClients waiting = new DynamicClients(
                List.of(new int[] {NET, 16}), source(), Duration.ofMinutes(1), Duration.ofMinutes(1), 1);
        Thread.sleep(100); // the thread waits for addresses to look up
        waiting.close();
        long deadline = System.nanoTime() + 2_000_000_000L;
        while (waiting.alive() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertThat(waiting.alive())
                .as("stopped by the interrupt, not after its 1 s poll")
                .isFalse();
    }
}
