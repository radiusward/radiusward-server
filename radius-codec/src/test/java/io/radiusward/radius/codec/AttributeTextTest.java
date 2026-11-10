/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class AttributeTextTest {

    private static final Dictionary DICTIONARY = DictionaryLoader.loadBundled();

    private static String roundTrip(String name, String text) {
        AttributeDef def = DICTIONARY.require(name);
        byte[] bytes = AttributeText.encode(def, text);
        return AttributeText.decode(def, new UnsafeBuffer(bytes), 0, bytes.length);
    }

    @Test
    void valuesByType() {
        assertThat(AttributeText.encode(DICTIONARY.require("Session-Timeout"), "3600"))
                .containsExactly(0, 0, 14, 16);
        assertThat(roundTrip("Session-Timeout", "3600")).isEqualTo("3600");
        assertThat(roundTrip("Service-Type", "Framed-User")).as("VALUE names").isEqualTo("Framed-User");
        assertThat(roundTrip("Service-Type", "2")).isEqualTo("Framed-User");
        assertThat(roundTrip("Acct-Status-Type", "0x00000003")).isEqualTo("Interim-Update");
        assertThat(roundTrip("Framed-IP-Address", "10.1.2.3")).isEqualTo("10.1.2.3");
        assertThat(roundTrip("Reply-Message", "Hello, wörld")).isEqualTo("Hello, wörld");
        assertThat(roundTrip("Class", "0x0102ff")).as("octets").isEqualTo("0x0102ff");
        assertThat(AttributeText.encode(DICTIONARY.require("NAS-IPv6-Address"), "2001:db8::1"))
                .hasSize(16);
        assertThat(roundTrip("Acct-Input-Gigawords", "4294967295")).isEqualTo("4294967295");
        assertThat(AttributeText.encode(DICTIONARY.require("Delegated-IPv6-Prefix"), "2001:db8:1200::/40"))
                .as("RFC 3162: reserved, length, the prefix's bytes")
                .containsExactly(0, 40, 0x20, 0x01, 0x0d, 0xb8, 0x12);
        assertThat(AttributeText.encode(DICTIONARY.require("Framed-IPv6-Prefix"), "2001:db8:ffff::/33"))
                .as("bits beyond the prefix cleared")
                .containsExactly(0, 33, 0x20, 0x01, 0x0d, 0xb8, 0x80);
        assertThat(roundTrip("Delegated-IPv6-Prefix", "2001:db8:1200:5600::/56"))
                .isEqualTo("2001:db8:1200:5600:0:0:0:0/56");
        assertThat(roundTrip("Framed-IPv6-Prefix", "::/0")).isEqualTo("0:0:0:0:0:0:0:0/0");
    }

    @Test
    void wrongValuesAreRejected() {
        assertThatThrownBy(() -> AttributeText.encode(DICTIONARY.require("Service-Type"), "Sometimes"))
                .hasMessageContaining("not a number or known value");
        assertThatThrownBy(() -> AttributeText.encode(DICTIONARY.require("Framed-IP-Address"), "host.example"))
                .as("never a DNS look-up")
                .hasMessageContaining("address literal");
        assertThatThrownBy(() -> AttributeText.encode(DICTIONARY.require("NAS-IP-Address"), "2001:db8::1"))
                .hasMessageContaining("IPv4");
        assertThatThrownBy(() -> AttributeText.encode(DICTIONARY.require("NAS-IPv6-Address"), "10.0.0.1"))
                .hasMessageContaining("IPv6");
        for (String bad : new String[] {"2001:db8::", "2001:db8::/129", "2001:db8::/x", "10.0.0.0/8"}) {
            assertThatThrownBy(() -> AttributeText.encode(DICTIONARY.require("Delegated-IPv6-Prefix"), bad))
                    .as(bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void oddLengthsDecodeAsHex() {
        AttributeDef ip = DICTIONARY.require("Framed-IP-Address");
        assertThat(AttributeText.decode(ip, new UnsafeBuffer(new byte[] {1, 2, 3}), 0, 3))
                .isEqualTo("0x010203");
        AttributeDef prefix = DICTIONARY.require("Delegated-IPv6-Prefix");
        assertThat(AttributeText.decode(prefix, new UnsafeBuffer(new byte[] {0, 64, 1}), 0, 3))
                .as("shorter than its length says")
                .isEqualTo("0x004001");
        assertThat(AttributeText.decode(prefix, new UnsafeBuffer(new byte[] {0}), 0, 1))
                .isEqualTo("0x00");
    }
}
