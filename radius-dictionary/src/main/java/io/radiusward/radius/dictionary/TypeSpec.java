/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

/** The data type of an attribute and its fixed length ({@code -1}: none), from a type token. */
record TypeSpec(DataType type, int length) {

    /** {@code octets}, {@code octets[16]}: a problem and {@code null} for an unknown type. */
    static TypeSpec parse(DictionaryFile file, String token) {
        DataType type = DataType.fromDictionaryName(token);
        if (type == null) {
            file.problem("unknown data type " + token);
            return null;
        }
        int length = -1;
        int bracket = token.indexOf('[');
        if (bracket >= 0) {
            if (!token.endsWith("]")) {
                file.problem("malformed type " + token);
                return null;
            }
            length = file.number(token.substring(bracket + 1, token.length() - 1));
            if (length < 0) {
                return null;
            }
        }
        return new TypeSpec(type, length);
    }
}
