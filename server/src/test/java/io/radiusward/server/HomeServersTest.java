/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** Choosing a home server, liveness and probes, discovered home servers (ADR 0037). */
class HomeServersTest {

    private static HomeServers homes(String poolType) {
        Map<String, String> settings = ProxyConfigTest.base();
        settings.put("pool.p.type", poolType);
        settings.put("proxy.dead.after", "10s");
        settings.put("proxy.status.interval", "30s");
        return new HomeServers(ProxyConfig.from(Config.of(settings)));
    }

    private static RadiusPacket request(String station) {
        byte[] bytes = station == null
                ? HandlerFixture.AccessRequestBuilder.userOnly("alice")
                : HandlerFixture.AccessRequestBuilder.pap(
                        "alice",
                        "pw",
                        HandlerFixture.AccessRequestBuilder.attribute(
                                31, station.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        RadiusPacket packet = new RadiusPacket();
        packet.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return packet;
    }

    @Test
    void failoverTakesTheFirstOneAlive() {
        HomeServers homes = homes("failover");
        int[] pool = homes.pool("p");
        assertThat(pool).hasSize(2);
        HomeState a = homes.get(pool[0]);
        HomeState b = homes.get(pool[1]);
        assertThat(a.index).isEqualTo(pool[0]);
        assertThat(homes.choose("p", pool, request(null))).isSameAs(a);
        a.alive = false;
        assertThat(homes.choose("p", pool, request(null))).isSameAs(b);
        b.alive = false;
        assertThat(homes.choose("p", pool, request(null)))
                .as("all dead: the first, as a request is as good a probe as a Status-Server")
                .isSameAs(a);
        homes.alive(a);
        assertThat(a.alive).isTrue();
        assertThat(homes.at(a.address)).isSameAs(a);
        assertThat(homes.pool("nope")).isNull();
    }

    @Test
    void loadBalancingKeepsADeviceOnOneHomeServer() {
        HomeServers homes = homes("load-balance");
        int[] pool = homes.pool("p");
        Set<HomeState> used = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            HomeState first = homes.choose("p", pool, request("aa-bb-" + i));
            assertThat(homes.choose("p", pool, request("aa-bb-" + i)))
                    .as("the same device")
                    .isSameAs(first);
            used.add(first);
        }
        assertThat(used).as("devices are spread").hasSize(2);
        homes.get(pool[1]).alive = false;
        for (int i = 0; i < 5; i++) {
            assertThat(homes.choose("p", pool, request("aa-bb-" + i))).isSameAs(homes.get(pool[0]));
        }
    }

    @Test
    void unansweredHomeServersDieAndAllAreProbed() {
        HomeServers homes = homes("failover");
        HomeState a = homes.get(homes.pool("p")[0]);
        List<HomeState> probed = new ArrayList<>();
        long now = 1_000_000_000L;
        homes.health(now, probed::add);
        assertThat(probed).as("every home server, at once").hasSize(2);
        a.waitingSince = now;
        homes.health(now + Duration.ofSeconds(9).toNanos(), probed::add);
        assertThat(a.alive).isTrue();
        assertThat(probed).as("not before the interval").hasSize(2);
        homes.health(now + Duration.ofSeconds(11).toNanos(), probed::add);
        assertThat(a.alive).as("no answer for proxy.dead.after").isFalse();
        homes.health(now + Duration.ofSeconds(31).toNanos(), probed::add);
        assertThat(probed).hasSize(4);
        homes.alive(a);
        assertThat(a.alive).isTrue();
        assertThat(a.waitingSince).isZero();
    }

    @Test
    void aDiscoveredHomeServerIsCreatedOncePerHostAndPort(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir)
            throws Exception {
        TestPki pki = new TestPki(dir, "home");
        Map<String, String> settings = ProxyConfigTest.base();
        settings.put("realm.roam.name", "roam.example");
        settings.put("realm.roam.discover", "true");
        settings.put("proxy.discovery.tls.ca", pki.caPem.toString());
        HomeServers homes = new HomeServers(ProxyConfig.from(Config.of(settings)));
        assertThat(homes.all()).hasSize(2);
        RealmDiscovery.Target target = new RealmDiscovery.Target("radsec.partner.example", 2083);
        int index = homes.discovered(target, InetAddress.getByName("10.0.0.9"));
        assertThat(homes.discovered(target, InetAddress.getByName("10.0.0.9"))).isEqualTo(index);
        assertThat(index).isEqualTo(2);
        assertThat(homes.get(index).index).isEqualTo(index);
        assertThat(homes.get(index).config.name()).isEqualTo("discovered:radsec.partner.example:2083");
        assertThat(homes.all()).hasSize(3);
        assertThat(homes.at(new InetSocketAddress("10.0.0.9", 2083)))
                .as("RadSec, not by UDP address")
                .isNull();
        homes.close();
    }
}
