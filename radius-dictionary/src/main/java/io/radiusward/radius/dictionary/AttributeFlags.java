/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** The flags of an ATTRIBUTE or DEFINE line ({@code has_tag}, {@code encrypt=1}, {@code array}, ...). */
final class AttributeFlags {

    private static final Set<String> KNOWN = Set.of(
            "has_tag",
            "encrypt",
            "concat",
            "internal",
            "array",
            "counter",
            "ref",
            "clone",
            "abinary",
            "secret",
            "precision",
            "extended",
            "long_extended",
            "enum",
            "key",
            "virtual",
            "length");

    static boolean known(String flag) {
        return KNOWN.contains(flag);
    }

    boolean hasTag;
    boolean concat;
    boolean internal;
    boolean array;
    String encrypt;
    final Map<String, String> options = new LinkedHashMap<>();

    /** Parses a comma-separated flags token; {@code false} to skip the line (an unknown flag in strict mode). */
    boolean parse(DictionaryFile file, String token) {
        for (String flag : token.split(",")) {
            if (flag.isEmpty()) {
                continue;
            }
            int eq = flag.indexOf('=');
            String name = eq >= 0 ? flag.substring(0, eq) : flag;
            String value = eq >= 0 ? flag.substring(eq + 1) : "";
            if (!KNOWN.contains(name)) {
                file.problem("unknown flag " + flag);
                return !file.strict();
            }
            switch (name) {
                case "has_tag" -> hasTag = true;
                case "concat" -> concat = true;
                case "internal" -> internal = true;
                case "array" -> array = true;
                case "encrypt" -> encrypt = encryptName(value);
                default -> options.put(name, value);
            }
        }
        return true;
    }

    void apply(AttributeDef def) {
        def.flags(hasTag, concat, internal, array, encrypt, options);
    }

    private static String encryptName(String value) {
        return switch (value) {
            case "1" -> "User-Password";
            case "2" -> "Tunnel-Password";
            case "3" -> "Ascend-Secret";
            default -> value;
        };
    }
}
