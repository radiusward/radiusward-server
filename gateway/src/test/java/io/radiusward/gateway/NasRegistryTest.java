/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NasRegistryTest {

    @Test
    void exactAndCidrLookups() throws Exception {
        NasRegistry registry = NasRegistry.from(Config.of(
                Map.of(
                        "nas.core.address", "10.255.0.1",
                        "nas.core.secret", "${env:CORE}",
                        "nas.core.vendor", "MikroTik",
                        "nas.aps.address", "10.20.0.0/16",
                        "nas.aps.secret", "ap-secret",
                        "nas.aps.message-authenticator", "required",
                        "nas.aps.id", "42"),
                Map.of("CORE", "s3cret")));
        NasClient core = registry.lookup(InetAddress.getByName("10.255.0.1"));
        assertThat(core.name()).isEqualTo("core");
        assertThat(new String(core.secret())).isEqualTo("s3cret");
        assertThat(core.vendor()).isEqualTo("mikrotik");
        assertThat(core.messageAuthenticator()).isEqualTo(NasClient.MessageAuthenticatorPolicy.OPTIONAL);
        assertThat(core.id()).isEqualTo(NasRegistry.fnv1a("core"));

        NasClient ap = registry.lookup(InetAddress.getByName("10.20.7.9"));
        assertThat(ap.name()).isEqualTo("aps");
        assertThat(ap.id()).isEqualTo(42);
        assertThat(ap.messageAuthenticator()).isEqualTo(NasClient.MessageAuthenticatorPolicy.REQUIRED);

        assertThat(registry.lookup(InetAddress.getByName("10.21.0.1"))).isNull();
        assertThat(registry.lookup(InetAddress.getByName("::1"))).isNull();
        assertThat(registry.clients()).hasSize(2);
    }

    @Test
    void stableIdsAcrossGateways() {
        assertThat(NasRegistry.fnv1a("core")).isEqualTo(NasRegistry.fnv1a("core"));
        assertThat(NasRegistry.fnv1a("core")).isNotEqualTo(NasRegistry.fnv1a("edge"));
    }

    @Test
    void configurationErrors() {
        assertThatThrownBy(() -> NasRegistry.from(Config.of(Map.of()))).hasMessageContaining("no NAS configured");
        assertThatThrownBy(() -> NasRegistry.from(Config.of(Map.of("nas.x.address", "10.0.0.1"))))
                .hasMessageContaining("nas.x.secret: required");
        assertThatThrownBy(
                        () -> NasRegistry.from(Config.of(Map.of("nas.x.address", "host.example", "nas.x.secret", "s"))))
                .hasMessageContaining("expected an IPv4 address");
        assertThatThrownBy(
                        () -> NasRegistry.from(Config.of(Map.of("nas.x.address", "10.0.0.0/40", "nas.x.secret", "s"))))
                .hasMessageContaining("invalid prefix length");
        assertThatThrownBy(() -> NasRegistry.from(Config.of(Map.of(
                        "nas.a.address",
                        "10.0.0.1",
                        "nas.a.secret",
                        "s",
                        "nas.b.address",
                        "10.0.0.1",
                        "nas.b.secret",
                        "s"))))
                .hasMessageContaining("duplicate address");
        assertThatThrownBy(() -> NasRegistry.from(Config.of(Map.of(
                        "nas.a.address",
                        "10.0.0.1",
                        "nas.a.secret",
                        "s",
                        "nas.a.id",
                        "5",
                        "nas.b.address",
                        "10.0.0.2",
                        "nas.b.secret",
                        "s",
                        "nas.b.id",
                        "5"))))
                .hasMessageContaining("already used");
    }

    @Test
    void deviceIdentityBehindNat() throws Exception {
        NasRegistry registry = NasRegistry.from(Config.of(Map.of(
                "nas.cloud.address", "0.0.0.0/0",
                "nas.cloud.secret", "s",
                "nas.cloud.identity", "NAS-Identifier, called-station-id",
                "nas.core.address", "10.255.0.1",
                "nas.core.secret", "s")));
        NasClient core = registry.lookup(InetAddress.getByName("10.255.0.1"));
        assertThat(core.identifiesDevices()).isFalse();
        NasClient cloud = registry.lookup(InetAddress.getByName("198.51.100.7"));
        assertThat(cloud.name()).isEqualTo("cloud");
        assertThat(cloud.identity())
                .containsExactly(NasClient.Identity.NAS_IDENTIFIER, NasClient.Identity.CALLED_STATION_ID);
        assertThat(cloud.identityFingerprint())
                .isNotEqualTo(core.identityFingerprint())
                .isNotEqualTo(new NasClient(
                                "x",
                                1,
                                0,
                                0,
                                new byte[0],
                                "default",
                                NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                                new NasClient.Identity[] {
                                    NasClient.Identity.CALLED_STATION_ID, NasClient.Identity.NAS_IDENTIFIER
                                })
                        .identityFingerprint());
    }

    @Test
    void identityConfigurationErrors() {
        assertThatThrownBy(() ->
                        NasRegistry.from(Config.of(Map.of("nas.any.address", "0.0.0.0/0", "nas.any.secret", "s"))))
                .hasMessageContaining("nas.any.identity");
        assertThatThrownBy(() -> NasRegistry.from(Config.of(Map.of(
                        "nas.x.address",
                        "10.0.0.0/8",
                        "nas.x.secret",
                        "s",
                        "nas.x.identity",
                        "source-ip, nas-identifier"))))
                .hasMessageContaining("cannot be combined");
        assertThatThrownBy(() -> NasRegistry.from(
                        Config.of(Map.of("nas.x.address", "10.0.0.0/8", "nas.x.secret", "s", "nas.x.identity", "mac"))))
                .hasMessageContaining("unknown value \"mac\"");
        assertThatThrownBy(() -> NasRegistry.from(Config.of(Map.of(
                        "nas.x.address",
                        "10.0.0.0/8",
                        "nas.x.secret",
                        "s",
                        "nas.x.identity",
                        "nas-identifier,nas-identifier"))))
                .hasMessageContaining("listed twice");
    }

    @Test
    void idleTimeoutPerEntry() throws Exception {
        NasRegistry registry = NasRegistry.from(Config.of(Map.of(
                "nas.wifi.address", "10.1.0.0/16",
                "nas.wifi.secret", "s",
                "nas.wifi.idle.timeout", "15m",
                "nas.bng.address", "10.2.0.1",
                "nas.bng.secret", "s")));
        assertThat(registry.lookup(InetAddress.getByName("10.1.2.3")).idleTimeoutMinutes())
                .isEqualTo(15);
        assertThat(registry.lookup(InetAddress.getByName("10.2.0.1")).idleTimeoutMinutes())
                .as("the cluster default")
                .isZero();
        for (String bad : List.of("90s", "30s", "0m", "65536m")) {
            assertThatThrownBy(() -> NasRegistry.from(Config.of(
                            Map.of("nas.x.address", "10.0.0.1", "nas.x.secret", "s", "nas.x.idle.timeout", bad))))
                    .as(bad)
                    .hasMessageContaining("nas.x.idle.timeout");
        }
    }
}
