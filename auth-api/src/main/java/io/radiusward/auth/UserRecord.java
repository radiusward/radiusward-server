/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

import java.util.List;

/**
 * A user as a store knows it, in FreeRADIUS terms: <b>check items</b> (credentials such as
 * {@code Cleartext-Password}, {@code Crypt-Password}, {@code NT-Password}; conditions such as {@code Auth-Type},
 * {@code Expiration}, {@code NAS-IP-Address == …}) and <b>reply items</b> sent in the Access-Accept, plus groups whose
 * items apply when their own check items match.
 */
public record UserRecord(String userName, List<AttributeItem> check, List<AttributeItem> reply, List<Group> groups) {

    public UserRecord {
        check = List.copyOf(check);
        reply = List.copyOf(reply);
        groups = List.copyOf(groups);
    }

    /** A group the user belongs to, in priority order. */
    public record Group(String name, List<AttributeItem> check, List<AttributeItem> reply) {
        public Group {
            check = List.copyOf(check);
            reply = List.copyOf(reply);
        }
    }
}
