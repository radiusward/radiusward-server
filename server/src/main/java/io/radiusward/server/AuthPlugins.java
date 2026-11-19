/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.auth.CredentialVerifierProvider;
import io.radiusward.auth.IdentityStoreProvider;
import java.util.List;

/**
 * Identity stores and credential verifiers given in code to a RADIUS server started in code (an embedded one, a test),
 * besides the plug-ins it finds on the class path and in {@code auth.plugins.dir}. They are used as plug-ins are:
 * {@code auth.store.<name>.type} or {@code auth.verifier.<name>.type} names a provider's type, and the server creates,
 * reloads and closes what the provider gives. A type given here must not also be a plug-in's.
 */
public record AuthPlugins(List<IdentityStoreProvider> stores, List<CredentialVerifierProvider> verifiers) {

    /** Only the plug-ins found on the class path and in the plug-ins directory. */
    public static final AuthPlugins NONE = new AuthPlugins(List.of(), List.of());

    public AuthPlugins {
        stores = List.copyOf(stores);
        verifiers = List.copyOf(verifiers);
    }

    public static AuthPlugins stores(IdentityStoreProvider... stores) {
        return new AuthPlugins(List.of(stores), List.of());
    }

    public AuthPlugins withVerifiers(CredentialVerifierProvider... verifiers) {
        return new AuthPlugins(stores, List.of(verifiers));
    }
}
