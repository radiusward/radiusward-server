/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ProvidersInCodeTest {

    private static final StoreContext CONTEXT = new StoreContext("mine", Map.of("colour", "blue"), 2);

    @Test
    void anIdentityStoreProviderInCodeCallsItsFactoryWithTheStoresContext() throws Exception {
        IdentityStoreProvider provider = IdentityStoreProvider.of("in-code", context -> new IdentityStore() {
            @Override
            public Optional<UserRecord> lookup(String userName) {
                return Optional.of(new UserRecord(
                        userName,
                        List.of(),
                        List.of(new AttributeItem(
                                "Reply-Message", "=", context.settings().get("colour"))),
                        List.of()));
            }

            @Override
            public void close() {}
        });
        assertThat(provider.type()).isEqualTo("in-code");
        assertThat(provider.create(CONTEXT)
                        .lookup("alice")
                        .orElseThrow()
                        .reply()
                        .getFirst()
                        .value())
                .isEqualTo("blue");
        assertThatThrownBy(
                        () -> IdentityStoreProvider.of("none", context -> null).create(CONTEXT))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("none");
        assertThatThrownBy(() -> IdentityStoreProvider.of(null, context -> null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void aCredentialVerifierProviderInCodeCallsItsFactory() throws Exception {
        CredentialVerifierProvider provider =
                CredentialVerifierProvider.of("check", context -> new CredentialVerifier() {
                    @Override
                    public Result verifyPassword(String userName, byte[] password) {
                        return context.name().equals("mine") ? Result.accepted(null) : Result.REJECTED;
                    }

                    @Override
                    public void close() {}
                });
        assertThat(provider.type()).isEqualTo("check");
        assertThat(provider.create(CONTEXT).verifyPassword("alice", new byte[0]).accepted())
                .isTrue();
        assertThatThrownBy(() ->
                        CredentialVerifierProvider.of("none", context -> null).create(CONTEXT))
                .isInstanceOf(NullPointerException.class);
    }
}
