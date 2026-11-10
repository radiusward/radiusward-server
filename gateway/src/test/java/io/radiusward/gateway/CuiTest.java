/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.auth.AttributeItem;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class CuiTest {

    static RadiusPacket request(byte[]... extra) {
        byte[] bytes = StoreAccessHandlerTest.AccessRequestBuilder.pap("alice", "pw", extra);
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return p;
    }

    static byte[] attribute(int type, String value) {
        return StoreAccessHandlerTest.AccessRequestBuilder.attribute(type, value.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void aStablePseudonymPerUserAndOperator() {
        Cui cui = Cui.from(Config.of(Map.of("auth.cui.key", "a-key-of-sixteen-chars")));
        String a = cui.value("alice", "1op.example");
        assertThat(a).hasSize(32).matches("[0-9a-f]+");
        assertThat(cui.value("ALICE", "1op.example"))
                .as("case of the user name")
                .isEqualTo(a);
        assertThat(cui.value("alice", "1other.example")).isNotEqualTo(a);
        assertThat(cui.value("bob", "1op.example")).isNotEqualTo(a);
        assertThat(Cui.from(Config.of(Map.of("auth.cui.key", "another-key-of-16-chars")))
                        .value("alice", "1op.example"))
                .isNotEqualTo(a);
    }

    @Test
    void onlyWhenAskedUnlessAlways() {
        Cui requested = Cui.from(Config.of(Map.of("auth.cui.key", "a-key-of-sixteen-chars")));
        List<AttributeItem> reply = new ArrayList<>();
        requested.apply(request(), "alice", reply);
        assertThat(reply).isEmpty();
        requested.apply(request(new byte[] {89, 3, 0}, attribute(126, "1op.example")), "alice", reply);
        assertThat(reply)
                .containsExactly(
                        new AttributeItem("Chargeable-User-Identity", "=", requested.value("alice", "1op.example")));

        Cui always = Cui.from(Config.of(Map.of("auth.cui.key", "a-key-of-sixteen-chars", "auth.cui.mode", "always")));
        List<AttributeItem> own = new ArrayList<>(List.of(new AttributeItem("Chargeable-User-Identity", "=", "x")));
        always.apply(request(), "alice", own);
        assertThat(own).as("a store's own CUI wins").hasSize(1);
        List<AttributeItem> fresh = new ArrayList<>();
        always.apply(request(), "alice", fresh);
        assertThat(fresh).singleElement().extracting(AttributeItem::value).isEqualTo(always.value("alice", ""));
    }

    @Test
    void configuration() {
        assertThat(Cui.from(Config.of(Map.of()))).isNull();
        assertThatThrownBy(() -> Cui.from(Config.of(Map.of("auth.cui.key", "short"))))
                .isInstanceOf(ConfigException.class);
        assertThatThrownBy(() -> Cui.from(
                        Config.of(Map.of("auth.cui.key", "a-key-of-sixteen-chars", "auth.cui.mode", "sometimes"))))
                .isInstanceOf(ConfigException.class);
    }
}
