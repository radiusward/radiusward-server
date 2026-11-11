/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.net;

import java.security.Security;

/**
 * How long the JVM keeps name lookups (ADR 0062). Members and gateways reach each other by name; on Kubernetes a
 * pod comes back with a new address under the same name, and the JVM's default of 30 s kept the old one long enough
 * for an election to fail for ~20 s during a rolling restart. One second is plenty for the few names they resolve.
 */
public final class DnsCache {

    static final String TTL = "networkaddress.cache.ttl";
    static final String NEGATIVE_TTL = "networkaddress.cache.negative.ttl";

    private DnsCache() {}

    /**
     * Sets a 1 s cache and no negative cache unless the operator chose values (security properties, or the
     * {@code sun.net.inetaddr.ttl} system properties). Call first in {@code main}, before any lookup.
     *
     * @return whether the short cache was applied
     */
    public static boolean shortLived() {
        if (System.getProperty("sun.net.inetaddr.ttl") != null || Security.getProperty(TTL) != null) {
            return false;
        }
        Security.setProperty(TTL, "1");
        if (System.getProperty("sun.net.inetaddr.negative.ttl") == null) {
            Security.setProperty(NEGATIVE_TTL, "0");
        }
        return true;
    }
}
