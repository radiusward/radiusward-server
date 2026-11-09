/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.file;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.ItemParser;
import io.radiusward.auth.UserRecord;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Parser for the FreeRADIUS users-file format (subset):
 *
 * <pre>
 * # comment
 * alice   Cleartext-Password := "arctangent", Expiration := "Jan 01 2030 00:00:00"
 *         Session-Timeout = 3600,
 *         Reply-Message = "Hello"
 * "user with spaces"  Crypt-Password := "$6$salt$hash"
 * </pre>
 *
 * An entry starts at column 0 with the user name and its check items; the indented lines after it are its reply
 * items, separated by commas. Values are bare words or double-quoted strings ({@code \"} and {@code \\} escapes); no
 * expansions. {@code DEFAULT} entries and {@code Fall-Through} are not supported (rejected with the line number), so a
 * file never means something other than it seems.
 */
final class UsersFile {

    private UsersFile() {}

    static Map<String, UserRecord> parse(List<String> lines) {
        return parse(lines, item -> null);
    }

    /**
     * @param replyCheck the problem with a reply item, or {@code null} (an unknown attribute is an error with its line
     *     number, not a silently missing reply attribute)
     */
    static Map<String, UserRecord> parse(List<String> lines, Function<AttributeItem, String> replyCheck) {
        Map<String, UserRecord> users = new LinkedHashMap<>();
        String user = null;
        List<AttributeItem> check = null;
        List<AttributeItem> reply = null;
        int entryLine = 0;
        for (int n = 0; n < lines.size(); n++) {
            String raw = lines.get(n);
            String trimmed = raw.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            if (!Character.isWhitespace(raw.charAt(0))) {
                if (user != null) {
                    add(users, user, check, reply, entryLine);
                }
                ItemParser c = new ItemParser(raw, n + 1);
                user = c.word();
                if (user.equals("DEFAULT")) {
                    throw c.error("DEFAULT entries are not supported");
                }
                check = new ArrayList<>();
                reply = new ArrayList<>();
                entryLine = n + 1;
                c.items(check);
            } else {
                if (user == null) {
                    throw new IllegalArgumentException("line " + (n + 1) + ": reply item before any user");
                }
                int from = reply.size();
                new ItemParser(raw, n + 1).items(reply);
                for (AttributeItem item : reply.subList(from, reply.size())) {
                    String problem = replyCheck.apply(item);
                    if (problem != null) {
                        throw new IllegalArgumentException("line " + (n + 1) + ": " + problem);
                    }
                }
            }
        }
        if (user != null) {
            add(users, user, check, reply, entryLine);
        }
        return users;
    }

    private static void add(
            Map<String, UserRecord> users,
            String user,
            List<AttributeItem> check,
            List<AttributeItem> reply,
            int line) {
        for (AttributeItem item : check) {
            if (item.attribute().equalsIgnoreCase("Fall-Through")) {
                throw new IllegalArgumentException("line " + line + ": Fall-Through is not supported");
            }
        }
        if (users.putIfAbsent(user, new UserRecord(user, check, reply, List.of())) != null) {
            throw new IllegalArgumentException("line " + line + ": user " + user + " defined twice");
        }
    }
}
