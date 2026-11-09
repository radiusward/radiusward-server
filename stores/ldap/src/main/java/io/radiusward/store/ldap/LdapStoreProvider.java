/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.ldap;

import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.IdentityStoreProvider;
import io.radiusward.auth.StoreContext;

/** {@code auth.store.<name>.type = ldap}. */
public final class LdapStoreProvider implements IdentityStoreProvider {

    @Override
    public String type() {
        return "ldap";
    }

    @Override
    public IdentityStore create(StoreContext context) {
        return new LdapStore(context);
    }
}
