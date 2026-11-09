/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthStoresTest {

    @TempDir
    Path dir;

    private Map<String, String> base() throws Exception {
        Path users = Files.writeString(dir.resolve("users"), "alice Cleartext-Password := \"a\"\n");
        Map<String, String> values = new HashMap<>();
        values.put("auth.stores", "staff, guests");
        values.put("auth.store.staff.type", "file");
        values.put("auth.store.staff.path", users.toString());
        values.put("auth.store.staff.chap", "true");
        values.put("auth.store.guests.type", "file");
        values.put("auth.store.guests.path", users.toString());
        values.put("auth.plugins.dir", dir.resolve("plugins").toString());
        return values;
    }

    @Test
    void storesInOrderWithPerNasOverride() throws Exception {
        Map<String, String> values = base();
        values.put("nas.lobby.auth.stores", "guests");
        values.put("auth.cache.ttl", "2s");
        try (AuthStores stores = AuthStores.from(Config.of(values), 4)) {
            assertThat(stores.order()).containsExactly("staff", "guests");
            assertThat(stores.storesFor("lobby")).containsExactly("guests");
            assertThat(stores.storesFor("core")).containsExactly("staff", "guests");
            assertThat(stores.chap()).containsEntry("staff", true).containsEntry("guests", false);
            assertThat(stores.cacheTtl()).isEqualTo(Duration.ofSeconds(2));
            assertThat(stores.cacheMax()).isEqualTo(100_000);
            assertThat(stores.bcryptMaxCost()).isEqualTo(14);
            assertThat(stores.stores().get("staff").lookup("alice")).isPresent();
        }
    }

    @Test
    void configurationErrorsNameTheKey() throws Exception {
        assertThatThrownBy(() -> AuthStores.from(Config.of(Map.of()), 1))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("auth.stores");

        Map<String, String> unknownType = base();
        unknownType.put("auth.store.guests.type", "ldap");
        assertThatThrownBy(() -> AuthStores.from(Config.of(unknownType), 1))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("auth.store.guests.type")
                .hasMessageContaining("file");

        Map<String, String> unknownStore = base();
        unknownStore.put("nas.lobby.auth.stores", "nope");
        assertThatThrownBy(() -> AuthStores.from(Config.of(unknownStore), 1))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("nas.lobby.auth.stores");

        Map<String, String> badCost = base();
        badCost.put("auth.bcrypt.max.cost", "40");
        assertThatThrownBy(() -> AuthStores.from(Config.of(badCost), 1))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("auth.bcrypt.max.cost");

        Map<String, String> badSetting = base();
        badSetting.remove("auth.store.guests.path");
        assertThatThrownBy(() -> AuthStores.from(Config.of(badSetting), 1))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("path");
    }

    @Test
    void replyVendorsFromTheNasVendorOrAnExplicitList() throws Exception {
        Map<String, String> values = base();
        values.put("nas.mx.vendor", "Juniper");
        values.put("nas.mt.vendor", "mikrotik");
        values.put("nas.mixed.vendor", "mikrotik");
        values.put("nas.mixed.reply.vendors", "Mikrotik, cisco");
        values.put("nas.lab.vendor", "default");
        values.put("nas.open.vendor", "mikrotik");
        values.put("nas.open.reply.vendors", "all");
        values.put("nas.plain.reply.vendors", "none");
        try (AuthStores stores = AuthStores.from(Config.of(values), 1, StoreAccessHandlerTest.DICTIONARY)) {
            assertThat(stores.replyVendors().get("mx")).containsExactlyInAnyOrder(2636, 4874);
            assertThat(stores.replyVendors().get("mt")).containsExactly(14988);
            assertThat(stores.replyVendors().get("mixed")).containsExactlyInAnyOrder(14988, 9);
            assertThat(stores.replyVendors().get("plain"))
                    .as("standard attributes only")
                    .isEmpty();
            assertThat(stores.replyVendors()).doesNotContainKeys("lab", "open");
        }
        Map<String, String> unknown = base();
        unknown.put("nas.x.reply.vendors", "no-such-vendor");
        assertThatThrownBy(() -> AuthStores.from(Config.of(unknown), 1, StoreAccessHandlerTest.DICTIONARY))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("nas.x.reply.vendors: unknown vendor no-such-vendor");
    }

    @Test
    void theFileStoreChecksReplyItemsAgainstTheDictionary() throws Exception {
        Map<String, String> values = base();
        Files.writeString(
                dir.resolve("users"),
                "alice Cleartext-Password := \"a\"\n    Session-Timeout = 60,\n    Mikrotik-Rate-Limit = \"1M\"\n");
        AuthStores.from(Config.of(values), 1, StoreAccessHandlerTest.DICTIONARY).close();
        Files.writeString(dir.resolve("users"), "alice Cleartext-Password := \"a\"\n    Sesion-Timeout = 60\n");
        assertThatThrownBy(() -> AuthStores.from(Config.of(values), 1, StoreAccessHandlerTest.DICTIONARY))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("line 2: reply item Sesion-Timeout is not in the dictionary");
        Files.writeString(dir.resolve("users"), "alice Cleartext-Password := \"a\"\n    Session-Timeout = soon\n");
        assertThatThrownBy(() -> AuthStores.from(Config.of(values), 1, StoreAccessHandlerTest.DICTIONARY))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("line 2: reply item Session-Timeout");
    }

    @Test
    void emptyPluginDirectoryIsFine() throws Exception {
        Files.createDirectories(dir.resolve("plugins"));
        Files.writeString(dir.resolve("plugins/readme.txt"), "not a jar");
        try (AuthStores stores = AuthStores.from(Config.of(base()), 1)) {
            assertThat(stores.stores()).containsOnlyKeys("staff", "guests");
            assertThat(stores.order())
                    .as("the order is kept apart from the map")
                    .containsExactly("staff", "guests");
        }
    }
}
