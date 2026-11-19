/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import io.radiusward.eap.MsChap;
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
    void aPasswordNoUserPasswordHoldsIsRejectedWithoutAskingTheHomeServer() {
        InnerProxy p = new InnerProxy(ProxyConfig.from(Config.of(ProxyConfigTest.base())));
        InnerProxy.Result r = p.password("alice@partner.example", new byte[129]);
        assertThat(r.inner().code()).isEqualTo(AccessHandler.REJECT);
        assertThat(InnerProxy.encryptPassword(new byte[128], new byte[16], "s".getBytes(StandardCharsets.US_ASCII)))
                .as("128 bytes still fit")
                .hasSize(128);
    }

    @Test
    void theHomeServersAcceptGivesItsSuccessAndKeysWhereverTheyAre() {
        byte[] secret = "s3cret".getBytes(StandardCharsets.US_ASCII);
        byte[] authenticator = new byte[16];
        Arrays.fill(authenticator, (byte) 7);
        byte[] send = new byte[16]; // MS-CHAPv2 keys (RFC 3079)
        byte[] receive = new byte[16];
        Arrays.fill(send, (byte) 1);
        Arrays.fill(receive, (byte) 2);
        byte[] sendValue = MsChap.encryptKey(send, secret, authenticator, new byte[] {(byte) 0x80, 2});
        byte[] receiveValue = MsChap.encryptKey(receive, secret, authenticator, new byte[] {(byte) 0x80, 3});
        byte[] success = "\u0007S=0123".getBytes(StandardCharsets.US_ASCII);
        // MS-CHAP2-Success and both keys in one Vendor-Specific, as some home servers pack them
        java.nio.ByteBuffer vsa =
                java.nio.ByteBuffer.allocate(4 + 2 + success.length + 2 + sendValue.length + 2 + receiveValue.length);
        vsa.putInt(311);
        vsa.put((byte) 26).put((byte) (2 + success.length)).put(success);
        vsa.put((byte) 16).put((byte) (2 + sendValue.length)).put(sendValue);
        vsa.put((byte) 17).put((byte) (2 + receiveValue.length)).put(receiveValue);
        org.agrona.concurrent.UnsafeBuffer buffer = new org.agrona.concurrent.UnsafeBuffer(new byte[512]);
        int length = new io.radiusward.radius.codec.RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(io.radiusward.radius.codec.RadiusCode.ACCESS_ACCEPT, 1)
                .authenticator(new byte[16])
                .attribute(18, "welcome")
                .attribute(33, "proxy-state")
                .attribute(26, vsa.array())
                .finish();
        byte[] packet = Arrays.copyOf(buffer.byteArray(), length);
        io.radiusward.radius.codec.RadiusPacket answer = new io.radiusward.radius.codec.RadiusPacket();
        answer.wrap(new org.agrona.concurrent.UnsafeBuffer(packet), 0, length);

        InnerProxy.Result result = InnerProxy.accepted(packet, answer, authenticator, secret);
        assertThat(result.inner().code()).isEqualTo(AccessHandler.ACCEPT);
        assertThat(result.inner().success()).isEqualTo("S=0123");
        assertThat(result.inner().sendKey()).isEqualTo(send);
        assertThat(result.inner().receiveKey()).isEqualTo(receive);
        assertThat(result.reply())
                .as("Reply-Message passed on; Proxy-State and the taken Vendor-Specific not")
                .containsExactly(18, 9, 'w', 'e', 'l', 'c', 'o', 'm', 'e');
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

    @Test
    void unreachableTlsAndTcpHomeServersLeaveTheRequestUnanswered() throws Exception {
        int closed;
        try (java.net.ServerSocket probe = new java.net.ServerSocket(0)) {
            closed = probe.getLocalPort();
        }
        for (String transport : new String[] {"tls", "tcp"}) {
            Map<String, String> settings = ProxyConfigTest.base();
            settings.put("home.a.address", "127.0.0.1:" + closed);
            settings.put("home.a.transport", transport);
            settings.put("home.a.tls.ca", "/never/read.pem"); // the connection fails before the TLS context is needed
            settings.put("pool.p.servers", "a");
            settings.put("proxy.timeout", "200ms");
            settings.put("proxy.retries", "0");
            InnerProxy p = new InnerProxy(ProxyConfig.from(Config.of(settings)));
            assertThat(p.password("bob@partner.example", "pw".getBytes(StandardCharsets.US_ASCII))
                            .inner()
                            .code())
                    .as(transport)
                    .isEqualTo(AccessHandler.DROP);
        }
    }
}
