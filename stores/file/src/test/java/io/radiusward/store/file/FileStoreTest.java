/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.file;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.UserRecord;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileStoreTest {

    @TempDir
    Path dir;

    @Test
    void usersFileFormat() {
        Map<String, UserRecord> users = UsersFile.parse(List.of(
                "# a comment",
                "alice   Cleartext-Password := \"arc tangent\", Expiration := \"Jan 01 2030 00:00:00\"",
                "        Session-Timeout = 3600,",
                "        Reply-Message = \"Hello, \\\"Alice\\\"\",  Cisco-AVPair += \"ip:inacl#1=permit ip any any\"",
                "",
                "\"bob smith\"  Crypt-Password := \"$6$salt$hash\", NAS-IP-Address == 10.0.0.1",
                "carol"));
        assertThat(users).containsOnlyKeys("alice", "bob smith", "carol");
        UserRecord alice = users.get("alice");
        assertThat(alice.check())
                .containsExactly(
                        new AttributeItem("Cleartext-Password", ":=", "arc tangent"),
                        new AttributeItem("Expiration", ":=", "Jan 01 2030 00:00:00"));
        assertThat(alice.reply())
                .containsExactly(
                        new AttributeItem("Session-Timeout", "=", "3600"),
                        new AttributeItem("Reply-Message", "=", "Hello, \"Alice\""),
                        new AttributeItem("Cisco-AVPair", "+=", "ip:inacl#1=permit ip any any"));
        assertThat(users.get("bob smith").check()).extracting(AttributeItem::op).containsExactly(":=", "==");
        assertThat(users.get("carol").check()).isEmpty();
        assertThat(alice.toString()).doesNotContain("arc tangent");
    }

    @Test
    void unsupportedOrBrokenEntriesAreRejectedWithTheLine() {
        assertThatThrownBy(() -> UsersFile.parse(List.of("DEFAULT Auth-Type := Reject")))
                .hasMessageContaining("line 1")
                .hasMessageContaining("DEFAULT");
        assertThatThrownBy(() -> UsersFile.parse(List.of("a Cleartext-Password := x", "a Cleartext-Password := y")))
                .hasMessageContaining("defined twice");
        assertThatThrownBy(() -> UsersFile.parse(List.of("a Fall-Through = Yes")))
                .hasMessageContaining("Fall-Through");
        assertThatThrownBy(() -> UsersFile.parse(List.of("   Session-Timeout = 1")))
                .hasMessageContaining("before any user");
        assertThatThrownBy(() -> UsersFile.parse(List.of("a Cleartext-Password := \"open")))
                .hasMessageContaining("unterminated");
        assertThatThrownBy(() -> UsersFile.parse(List.of("a Cleartext-Password x")))
                .hasMessageContaining("operator");
        assertThatThrownBy(() -> UsersFile.parse(List.of("a Cleartext-Password := x Session-Timeout = 1")))
                .hasMessageContaining("expected ','");
    }

    @Test
    void reloadedWhenChangedAndKeptWhenBroken() throws Exception {
        Path file = dir.resolve("users");
        Files.writeString(file, "alice Cleartext-Password := one\n");
        try (IdentityStore store = new FileStoreProvider()
                .create(new StoreContext("local", Map.of("path", file.toString(), "reload.interval", "1ms"), 4))) {
            assertThat(store.lookup("alice")).isPresent();
            assertThat(store.lookup("bob")).isEmpty();
            Files.writeString(file, "alice Cleartext-Password := one\nbob Cleartext-Password := two\n");
            Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() + 2000));
            Thread.sleep(5);
            assertThat(store.lookup("bob")).as("reloaded").isPresent();
            Files.writeString(file, "DEFAULT Auth-Type := Accept\n");
            Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() + 4000));
            Thread.sleep(5);
            assertThat(store.lookup("bob"))
                    .as("a broken file keeps the previous users")
                    .isPresent();
        }
        assertThatThrownBy(() -> new FileStoreProvider()
                        .create(new StoreContext(
                                "local", Map.of("path", dir.resolve("missing").toString()), 4)))
                .hasMessageContaining("cannot read");
        assertThatThrownBy(() -> new FileStoreProvider().create(new StoreContext("local", Map.of(), 4)))
                .hasMessageContaining("auth.store.local.path is required");
        assertThat(new FileStoreProvider().type()).isEqualTo("file");
    }

    @Test
    void replyItemsAreCheckedAtLoadAndReload() throws Exception {
        Path file = dir.resolve("checked");
        Files.writeString(file, "alice Cleartext-Password := \"a\"\n    Session-Timeout = 60\n");
        StoreContext context = new StoreContext(
                "local",
                Map.of("path", file.toString(), "reload.interval", "1ms"),
                4,
                item -> item.value().equals("bad") ? "reply item " + item.attribute() + ": bad value" : null);
        try (IdentityStore store = new FileStoreProvider().create(context)) {
            Files.writeString(file, "alice Cleartext-Password := \"a\"\n    Session-Timeout = bad\n");
            Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
            Thread.sleep(5);
            assertThat(store.lookup("alice").orElseThrow().reply())
                    .as("the broken reload keeps the previous users")
                    .containsExactly(new AttributeItem("Session-Timeout", "=", "60"));
        }
        assertThatThrownBy(() -> new FileStoreProvider().create(context))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("line 2: reply item Session-Timeout: bad value");
    }
}
