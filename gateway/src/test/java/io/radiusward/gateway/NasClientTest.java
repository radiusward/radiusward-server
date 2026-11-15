/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class NasClientTest {

    @Test
    void theBuilderStartsFromTheConfigurationDefaults() {
        NasClient c = NasClient.builder("ap", 7).network(0x0A000000, 8).build();
        assertThat(c.vendor()).isEqualTo("default");
        assertThat(c.messageAuthenticator()).isEqualTo(NasClient.MessageAuthenticatorPolicy.OPTIONAL);
        assertThat(c.accessMessageAuthenticator()).isEqualTo(NasClient.MessageAuthenticatorPolicy.REQUIRED);
        assertThat(c.identifiesDevices()).isFalse();
        assertThat(c.idleTimeoutMinutes()).isZero();
        assertThat(c.ipv6()).isFalse();
        assertThat(c.matches(0x0A010203)).isTrue();
    }

    @Test
    void anotherSecretKeepsEverythingElseAnIpv6NetworkToo() {
        byte[] network6 = new byte[16];
        network6[0] = 0x20;
        network6[1] = 0x01;
        NasClient udp = NasClient.builder("campus6", 9)
                .network6(network6, 64)
                .secret("udp".getBytes(StandardCharsets.US_ASCII))
                .vendor("cisco")
                .messageAuthenticator(NasClient.MessageAuthenticatorPolicy.REQUIRED)
                .identity(NasClient.Identity.NAS_IDENTIFIER)
                .idleTimeoutMinutes(15)
                .accessMessageAuthenticator(NasClient.MessageAuthenticatorPolicy.OPTIONAL)
                .build();
        NasClient radsec = udp.withSecret("radsec".getBytes(StandardCharsets.US_ASCII));
        assertThat(radsec.secret()).isEqualTo("radsec".getBytes(StandardCharsets.US_ASCII));
        assertThat(radsec.ipv6()).as("the IPv6 network survives").isTrue();
        assertThat(radsec.network6()).isEqualTo(network6);
        assertThat(radsec.prefixLength()).isEqualTo(64);
        assertThat(radsec.identityFingerprint()).isEqualTo(udp.identityFingerprint());
        assertThat(radsec).usingRecursiveComparison().ignoringFields("secret").isEqualTo(udp);
    }
}
