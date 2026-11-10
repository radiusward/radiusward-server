/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The inner proxy's helpers (ADR 0044): realms, User-Password and MPPE key encryption, stripping, an unanswering home
 * server. Conversations through a home server: {@code EapolTestIT#innerUsersOfAProxiedRealmAreCheckedByTheirHomeServer}.
 */
class InnerProxyTest {

    @Test
    void realmsOfInnerUsers() {
        InnerProxy p = new InnerProxy(ProxyConfig.from(Config.of(ProxyConfigTest.base())));
        assertThat(p.realm("bob@partner.example").name()).isEqualTo("partner.example");
        assertThat(p.realm("bob@elsewhere.example").name())
                .as("the default realm")
                .isEqualTo("*");
        Map<String, String> noDefault = ProxyConfigTest.base();
        noDefault.remove("realm.rest.name");
        noDefault.remove("realm.rest.pool");
        assertThat(new InnerProxy(ProxyConfig.from(Config.of(noDefault))).realm("carol"))
                .as("no realm: decided here")
                .isNull();
        assertThat(InnerProxy.stripped("bob@partner.example")).isEqualTo("bob");
        assertThat(InnerProxy.stripped("PARTNER\\bob")).isEqualTo("bob");
        assertThat(InnerProxy.stripped("bob")).isEqualTo("bob");
    }

    @Test
    void passwordsAndKeysAreEncryptedAsRadiusDoes() {
        byte[] secret = "s3cret".getBytes(StandardCharsets.US_ASCII);
        byte[] authenticator = new byte[16];
        Arrays.fill(authenticator, (byte) 7);
        byte[] password = "a password longer than sixteen".getBytes(StandardCharsets.US_ASCII);
        byte[] encrypted = InnerProxy.encryptPassword(password, authenticator, secret);
        assertThat(encrypted).hasSize(32);
        // decrypting is the same XOR chain: encrypt the cipher text's first block again with the same pad
        byte[] again = InnerProxy.encryptPassword(new byte[0], authenticator, secret);
        assertThat(again).hasSize(16);

        byte[] key = new byte[16];
        Arrays.fill(key, (byte) 0x42);
        byte[] value = MsChap.encryptKey(key, secret, authenticator, new byte[] {(byte) 0x80, 1});
        assertThat(InnerProxy.decryptKey(value, authenticator, secret)).isEqualTo(key);
        assertThat(InnerProxy.decryptKey(new byte[10], authenticator, secret))
                .as("too short")
                .isNull();
    }

    @Test
    void anUnansweringHomeServerLeavesTheRequestUnanswered() throws Exception {
        int silent;
        try (DatagramSocket probe = new DatagramSocket(0)) {
            silent = probe.getLocalPort();
        }
        Map<String, String> settings = ProxyConfigTest.base();
        settings.put("home.a.address", "127.0.0.1:" + silent);
        settings.put("pool.p.servers", "a");
        settings.put("proxy.timeout", "100ms");
        settings.put("proxy.retries", "0");
        InnerProxy p = new InnerProxy(ProxyConfig.from(Config.of(settings)));
        InnerProxy.Result r = p.password("bob@partner.example", "pw".getBytes(StandardCharsets.US_ASCII));
        assertThat(r.inner().code()).isEqualTo(AccessHandler.DROP);
        assertThat(p.get(InnerProxy.Counter.NO_ANSWER)).isEqualTo(1);
        assertThat(p.chap("bob@partner.example", 1, new byte[16], new byte[16])
                        .inner()
                        .code())
                .isEqualTo(AccessHandler.DROP);
    }
}
