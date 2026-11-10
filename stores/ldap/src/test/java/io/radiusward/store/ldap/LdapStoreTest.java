/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.ldap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The LDAP store and verifier against a Samba AD domain controller (Docker). */
class LdapStoreTest {

    static final AttributeItem REJECT = new AttributeItem("Auth-Type", ":=", "Reject");

    @TempDir
    static Path dir;

    @BeforeAll
    static void directory() {
        SambaAd.start();
    }

    /** LDAPS with the domain's CA: domain controllers refuse simple binds without transport encryption. */
    static Map<String, String> settings() {
        Map<String, String> s = new HashMap<>();
        s.put("url", SambaAd.ldapsUrl());
        try {
            s.put("tls.ca", SambaAd.ca(dir).toString());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        s.put("bind.dn", SambaAd.SERVICE);
        s.put("bind.password", SambaAd.SERVICE_PASSWORD);
        s.put("base.dn", SambaAd.BASE);
        return s;
    }

    static LdapStore store(Map<String, String> settings) {
        return (LdapStore) new LdapStoreProvider().create(new StoreContext("ad", settings, 2));
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void usersGroupsPoliciesAndAccountState() throws Exception {
        Map<String, String> s = settings();
        s.put("require.groups", "VPN Users, Contractors");
        s.put("policy.10.group", "Staff");
        s.put("policy.10.reply", "Filter-Id = \"staff\", Session-Timeout = 28800");
        s.put("policy.20.group", "VPN Users");
        s.put("policy.20.check", "NAS-Port-Type == Virtual");
        s.put("policy.20.reply", "Class += \"vpn\"");
        s.put("reply.Reply-Message", "givenName");
        try (LdapStore store = store(s)) {
            UserRecord alice = store.lookup("alice").orElseThrow();
            assertThat(alice.check()).doesNotContain(REJECT);
            assertThat(alice.reply()).containsExactly(new AttributeItem("Reply-Message", "=", "Alice"));
            assertThat(alice.groups()).extracting(UserRecord.Group::name).containsExactly("Staff", "VPN Users");
            assertThat(alice.groups().get(0).reply())
                    .containsExactly(
                            new AttributeItem("Filter-Id", "=", "staff"),
                            new AttributeItem("Session-Timeout", "=", "28800"));
            assertThat(alice.groups().get(1).check())
                    .containsExactly(new AttributeItem("NAS-Port-Type", "==", "Virtual"));

            assertThat(store.lookup("bob").orElseThrow().check())
                    .as("not in a required group")
                    .contains(REJECT);
            assertThat(store.lookup("carol").orElseThrow().check())
                    .as("disabled")
                    .contains(REJECT);
            assertThat(store.lookup("nobody")).isEmpty();
            assertThat(store.lookup("*"))
                    .as("the name is escaped, not a wildcard")
                    .isEmpty();
            assertThat(store.lookup("alice)(objectClass=*")).isEmpty();
        }
    }

    @Test
    void domainPrefixesAndRealmsAreStrippedForTheLookup() throws Exception {
        try (LdapStore store = store(settings())) {
            assertThat(store.lookup("CORP\\alice")).isPresent();
            assertThat(store.lookup("alice@corp.test")).isPresent();
            assertThat(store.lookup("CORP\\alice").orElseThrow().userName())
                    .as("the name as sent")
                    .isEqualTo("CORP\\alice");
        }
        Map<String, String> exact = settings();
        exact.put("strip.domain", "false");
        try (LdapStore store = store(exact)) {
            assertThat(store.lookup("CORP\\alice")).isEmpty();
        }
        try (CredentialVerifier verifier = new LdapVerifierProvider().create(new StoreContext("ad", settings(), 2))) {
            assertThat(verifier.verifyPassword("CORP\\alice", utf8("Alice-Passw0rd!"))
                            .accepted())
                    .isTrue();
        }
    }

    @Test
    void nestedGroupsThroughTheInChainRule() throws Exception {
        Map<String, String> s = settings();
        s.put("group.nested", "true");
        s.put("require.groups", "Remote Workers");
        try (LdapStore store = store(s)) {
            UserRecord alice = store.lookup("alice").orElseThrow();
            assertThat(alice.check()).as("member through VPN Users").doesNotContain(REJECT);
            assertThat(store.lookup("bob").orElseThrow().check()).contains(REJECT);
        }
        Map<String, String> direct = settings();
        direct.put("require.groups", "Remote Workers");
        try (LdapStore store = store(direct)) {
            assertThat(store.lookup("alice").orElseThrow().check())
                    .as("memberOf lists only direct groups")
                    .contains(REJECT);
        }
    }

    @Test
    void passwordsAreCheckedByBindingAsTheUser() throws Exception {
        try (CredentialVerifier verifier = new LdapVerifierProvider().create(new StoreContext("ad", settings(), 2))) {
            assertThat(verifier.verifyPassword("alice", utf8("Alice-Passw0rd!")).accepted())
                    .isTrue();
            assertThat(verifier.verifyPassword("alice", utf8("wrong")).accepted())
                    .isFalse();
            assertThat(verifier.verifyPassword("alice", new byte[0]).accepted())
                    .as("an empty password is never an anonymous bind")
                    .isFalse();
            assertThat(verifier.verifyPassword("carol", utf8("Carol-Passw0rd!")).accepted())
                    .as("disabled")
                    .isFalse();
            assertThat(verifier.verifyPassword("nobody", utf8("x")).accepted()).isFalse();
            assertThat(verifier.verifyMsChap("alice", new byte[8], new byte[24], true)
                            .outcome())
                    .isEqualTo(CredentialVerifier.Outcome.UNSUPPORTED);
        }
    }

    @Test
    void ldapsNeedsTheDomainsCaAndPlainLdapIsRefused() throws Exception {
        Map<String, String> untrusted = settings();
        untrusted.remove("tls.ca");
        try (LdapStore store = store(untrusted)) {
            assertThatThrownBy(() -> store.lookup("alice"))
                    .as("the JDK's default CAs do not know the domain's CA")
                    .isInstanceOf(StoreUnavailableException.class);
        }
        Map<String, String> plain = settings();
        plain.put("url", SambaAd.ldapUrl());
        plain.remove("tls.ca");
        try (LdapStore store = store(plain)) {
            assertThatThrownBy(() -> store.lookup("alice"))
                    .as("a password over plain LDAP")
                    .isInstanceOf(StoreUnavailableException.class)
                    .hasMessageContaining("encryption required");
        }
    }

    @Test
    void outagesAndWrongServiceCredentialsAreUnavailable() throws Exception {
        int closed;
        try (ServerSocket socket = new ServerSocket(0)) {
            closed = socket.getLocalPort();
        }
        Map<String, String> down = settings();
        down.put("url", "ldaps://127.0.0.1:" + closed);
        try (LdapStore store = store(down)) {
            assertThatThrownBy(() -> store.lookup("alice")).isInstanceOf(StoreUnavailableException.class);
        }
        Map<String, String> failover = settings();
        failover.put("url", "ldaps://127.0.0.1:" + closed + " " + SambaAd.ldapsUrl());
        try (LdapStore store = store(failover)) {
            assertThat(store.lookup("alice")).as("the second server answers").isPresent();
        }
        Map<String, String> badBind = settings();
        badBind.put("bind.password", "wrong");
        try (LdapStore store = store(badBind)) {
            assertThatThrownBy(() -> store.lookup("alice"))
                    .isInstanceOf(StoreUnavailableException.class)
                    .hasMessageContaining("bind.dn rejected");
        }
    }

    @Test
    void settingsAreChecked() {
        Map<String, String> s = settings();
        s.put("url", "http://dc");
        assertThatThrownBy(() -> store(s)).hasMessageContaining("ldap:// or ldaps://");
        Map<String, String> anonymous = settings();
        anonymous.remove("bind.dn");
        anonymous.remove("bind.password");
        assertThatThrownBy(() -> store(anonymous))
                .as("anonymous searches only on request")
                .hasMessageContaining("bind.anonymous");
        anonymous.put("bind.anonymous", "true");
        store(anonymous).close();
        Map<String, String> filter = settings();
        filter.put("user.filter", "(uid=alice)");
        assertThatThrownBy(() -> store(filter)).hasMessageContaining("{0}");
        Map<String, String> policy = settings();
        policy.put("policy.1.reply", "Filter-Id = x");
        assertThatThrownBy(() -> store(policy)).hasMessageContaining("policy.1.group is required");
        Map<String, String> items = settings();
        items.put("policy.1.group", "Staff");
        items.put("policy.1.reply", "Filter-Id x");
        assertThatThrownBy(() -> store(items)).hasMessageContaining("auth.store.ad.policy.1.reply");
        Map<String, String> ca = settings();
        ca.put("tls.ca", "/no/such/ca.pem");
        assertThatThrownBy(() -> store(ca)).hasMessageContaining("tls.ca");
        Map<String, String> mixed = settings();
        mixed.put("url", "ldap://dc1 " + SambaAd.ldapsUrl());
        assertThatThrownBy(() -> store(mixed)).hasMessageContaining("applies to ldaps:// only");
        assertThat(List.of(LdapStore.IN_CHAIN)).isNotEmpty();
    }
}
