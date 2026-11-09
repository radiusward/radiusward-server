/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.file;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.UserRecord;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

    private static final String[] OPS = {":=", "==", "+=", "!=", ">=", "<=", "=~", "!~", "=*", "!*", "=", ">", "<"};

    private UsersFile() {}

    static Map<String, UserRecord> parse(List<String> lines) {
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
                Cursor c = new Cursor(raw, n + 1);
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
                new Cursor(raw, n + 1).items(reply);
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

    /** Reads words, operators and values from one line. */
    private static final class Cursor {
        private final String text;
        private final int line;
        private int at;

        Cursor(String text, int line) {
            this.text = text;
            this.line = line;
        }

        IllegalArgumentException error(String message) {
            return new IllegalArgumentException("line " + line + ": " + message);
        }

        private void skipSpaces() {
            while (at < text.length() && Character.isWhitespace(text.charAt(at))) {
                at++;
            }
        }

        boolean end() {
            skipSpaces();
            return at >= text.length() || text.charAt(at) == '#';
        }

        String word() {
            skipSpaces();
            if (at < text.length() && text.charAt(at) == '"') {
                return quoted();
            }
            int start = at;
            while (at < text.length()
                    && !Character.isWhitespace(text.charAt(at))
                    && text.charAt(at) != ','
                    && "=:!<>+".indexOf(text.charAt(at)) < 0) {
                at++;
            }
            if (start == at) {
                throw error("expected a name or value at column " + (at + 1));
            }
            return text.substring(start, at);
        }

        private String quoted() {
            StringBuilder sb = new StringBuilder();
            at++;
            while (at < text.length()) {
                char ch = text.charAt(at++);
                if (ch == '"') {
                    return sb.toString();
                }
                if (ch == '\\' && at < text.length()) {
                    sb.append(text.charAt(at++));
                } else {
                    sb.append(ch);
                }
            }
            throw error("unterminated string");
        }

        String op() {
            skipSpaces();
            for (String op : OPS) {
                if (text.startsWith(op, at)) {
                    at += op.length();
                    return op;
                }
            }
            throw error("expected an operator (:=, =, ==, +=, …) at column " + (at + 1));
        }

        /** {@code name op value} items separated by commas, until the end of the line. */
        void items(List<AttributeItem> into) {
            while (!end()) {
                String name = word();
                String op = op();
                String value = valueToken();
                into.add(new AttributeItem(name, op, value));
                skipSpaces();
                if (at < text.length() && text.charAt(at) == ',') {
                    at++;
                } else if (!end()) {
                    throw error("expected ',' between items at column " + (at + 1));
                }
            }
        }

        private String valueToken() {
            skipSpaces();
            if (at < text.length() && text.charAt(at) == '"') {
                return quoted();
            }
            int start = at;
            while (at < text.length() && !Character.isWhitespace(text.charAt(at)) && text.charAt(at) != ',') {
                at++;
            }
            if (start == at) {
                throw error("expected a value at column " + (at + 1));
            }
            return text.substring(start, at);
        }
    }
}
