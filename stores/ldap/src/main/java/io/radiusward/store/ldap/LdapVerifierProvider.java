/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.ldap;

import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.CredentialVerifierProvider;
import io.radiusward.auth.StoreContext;

/** {@code auth.verifier.<name>.type = ldap}: PAP by binding as the user. */
public final class LdapVerifierProvider implements CredentialVerifierProvider {

    @Override
    public String type() {
        return "ldap";
    }

    @Override
    public CredentialVerifier create(StoreContext context) {
        return new LdapVerifier(context);
    }
}
