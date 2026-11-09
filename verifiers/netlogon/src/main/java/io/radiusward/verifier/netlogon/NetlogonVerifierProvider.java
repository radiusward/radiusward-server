/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.CredentialVerifierProvider;
import io.radiusward.auth.StoreContext;

/** {@code auth.verifier.<name>.type = netlogon}: Active Directory over Netlogon. */
public final class NetlogonVerifierProvider implements CredentialVerifierProvider {

    @Override
    public String type() {
        return "netlogon";
    }

    @Override
    public CredentialVerifier create(StoreContext context) {
        return new NetlogonVerifier(context);
    }
}
