/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codegen;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import javax.lang.model.SourceVersion;

/** Turns dictionary names into Java identifiers. */
final class JavaNames {

    private JavaNames() {}

    /** {@code Acct-Status-Type} → {@code ACCT_STATUS_TYPE}, {@code 3GPP-IMSI} → {@code _3GPP_IMSI}. */
    static String constant(String name) {
        String upper =
                name.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+", "_").replaceAll("^_+|_+$", "");
        if (upper.isEmpty()) {
            upper = "UNNAMED";
        }
        if (Character.isDigit(upper.charAt(0)) || SourceVersion.isKeyword(upper.toLowerCase(Locale.ROOT))) {
            upper = "_" + upper;
        }
        return upper;
    }

    /** {@code statusType} → {@code STATUS_TYPE}, {@code nasIpv6Address} → {@code NAS_IPV6_ADDRESS}. */
    static String fieldConstant(String camel) {
        return camel.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toUpperCase(Locale.ROOT);
    }

    /** {@code Mikrotik} → {@code Mikrotik}, {@code ADSL-Forum} → {@code AdslForum}. */
    static String type(String name) {
        StringBuilder sb = new StringBuilder();
        for (String part : name.split("[^A-Za-z0-9]+")) {
            if (part.isEmpty()) {
                continue;
            }
            boolean allUpper = part.equals(part.toUpperCase(Locale.ROOT));
            String rest = allUpper ? part.substring(1).toLowerCase(Locale.ROOT) : part.substring(1);
            sb.append(Character.toUpperCase(part.charAt(0))).append(rest);
        }
        if (sb.isEmpty() || Character.isDigit(sb.charAt(0))) {
            sb.insert(0, 'V');
        }
        return sb.toString();
    }

    /** Hands out unique names: a clash gets {@code _2}, {@code _3}, ... appended. */
    static final class Unique {
        private final Set<String> used = new HashSet<>();

        String next(String candidate) {
            String name = candidate;
            for (int n = 2; !used.add(name); n++) {
                name = candidate + "_" + n;
            }
            return name;
        }
    }
}
