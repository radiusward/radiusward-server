/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

/**
 * Creates {@link CredentialVerifier}s of one type ({@code auth.verifier.<name>.type}); found through
 * {@link java.util.ServiceLoader} on the class path and in {@code auth.plugins.dir}, like identity stores (ADR 0025).
 */
public interface CredentialVerifierProvider {

    /** The value of {@code auth.verifier.<name>.type} this provider serves, e.g. {@code netlogon}, {@code ldap}. */
    String type();

    /**
     * @param context the verifier's name and its {@code auth.verifier.<name>.*} settings
     * @throws IllegalArgumentException for a missing or invalid setting
     */
    CredentialVerifier create(StoreContext context);
}
