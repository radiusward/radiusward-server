/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

import java.util.Objects;
import java.util.function.Function;

/**
 * Creates identity stores of one type ({@code auth.store.<name>.type}); found with {@link java.util.ServiceLoader}
 * on the class path and in the plug-ins directory ({@code META-INF/services/io.radiusward.auth.IdentityStoreProvider}),
 * or given in code to a RADIUS server that is started in code (an embedded one, a test), e.g. with {@link #of}.
 */
public interface IdentityStoreProvider {

    /** The {@code type} value this provider serves, e.g. {@code sql}, {@code file}. */
    String type();

    /**
     * Called for each {@code auth.store.<name>} of this type, and again when the configuration is reloaded; the server
     * closes the stores it replaces and, at shutdown, the ones it has.
     */
    IdentityStore create(StoreContext context);

    /** A provider in code: {@code create} calls {@code factory} with the store's name and settings. */
    static IdentityStoreProvider of(String type, Function<StoreContext, IdentityStore> factory) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(factory, "factory");
        return new IdentityStoreProvider() {
            @Override
            public String type() {
                return type;
            }

            @Override
            public IdentityStore create(StoreContext context) {
                return Objects.requireNonNull(factory.apply(context), "the factory of " + type + " returned null");
            }
        };
    }
}
