/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

import java.util.Objects;
import java.util.function.Function;

/**
 * Creates {@link CredentialVerifier}s of one type ({@code auth.verifier.<name>.type}); found through
 * {@link java.util.ServiceLoader} on the class path and in {@code auth.plugins.dir}, like identity stores (ADR 0025), or
 * given in code to a RADIUS server that is started in code, e.g. with {@link #of}.
 */
public interface CredentialVerifierProvider {

    /** The value of {@code auth.verifier.<name>.type} this provider serves, e.g. {@code netlogon}, {@code ldap}. */
    String type();

    /**
     * @param context the verifier's name and its {@code auth.verifier.<name>.*} settings
     * @throws IllegalArgumentException for a missing or invalid setting
     */
    CredentialVerifier create(StoreContext context);

    /** A provider in code: {@code create} calls {@code factory} with the verifier's name and settings. */
    static CredentialVerifierProvider of(String type, Function<StoreContext, CredentialVerifier> factory) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(factory, "factory");
        return new CredentialVerifierProvider() {
            @Override
            public String type() {
                return type;
            }

            @Override
            public CredentialVerifier create(StoreContext context) {
                return Objects.requireNonNull(factory.apply(context), "the factory of " + type + " returned null");
            }
        };
    }
}
