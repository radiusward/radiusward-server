/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.ldap;

import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.StoreUnavailableException;
import java.util.List;

/**
 * Checks PAP passwords by binding to the directory as the user ({@code auth.verifier.<name>.type = ldap}): the
 * service account finds the user's DN with {@code user.filter}, then a bind with the password decides. The directory
 * applies its own rules (disabled, expired, locked accounts, password age). MS-CHAP cannot be checked over LDAP; it
 * needs the Netlogon verifier.
 */
final class LdapVerifier implements CredentialVerifier {

    private final LdapSettings settings;
    private final Directory directory;

    LdapVerifier(StoreContext context) {
        this.settings = LdapSettings.from(context, "auth.verifier." + context.name() + ".");
        this.directory = new Directory(settings);
    }

    @Override
    public Result verifyPassword(String userName, byte[] password) throws StoreUnavailableException {
        List<Directory.Entry> found =
                directory.search(settings.userFilter(), new Object[] {userName}, new String[] {"1.1"}, 2);
        if (found.size() != 1) {
            return Result.REJECTED; // unknown or ambiguous: never guess which entry is meant
        }
        return directory.bind(found.get(0).dn(), password) ? Result.accepted(null) : Result.REJECTED;
    }

    @Override
    public void close() {
        directory.close();
    }
}
