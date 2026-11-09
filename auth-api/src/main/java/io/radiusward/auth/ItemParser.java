/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

import java.util.List;

/**
 * Reads attribute items in the users-file syntax — {@code name op value}, separated by commas, values optionally quoted
 * with {@code \"} and {@code \\} escapes — for stores that take items from text (a users file, a directory's group
 * policies).
 */
public final class ItemParser {

    /** Operators, longest first. */
    public static final String[] OPS = {":=", "==", "+=", "!=", ">=", "<=", "=~", "!~", "=*", "!*", "=", ">", "<"};

    private final String text;
    private final int line;
    private int at;

    public ItemParser(String text, int line) {
        this.text = text;
        this.line = line;
    }

    public IllegalArgumentException error(String message) {
        return new IllegalArgumentException("line " + line + ": " + message);
    }

    private void skipSpaces() {
        while (at < text.length() && Character.isWhitespace(text.charAt(at))) {
            at++;
        }
    }

    public boolean end() {
        skipSpaces();
        return at >= text.length() || text.charAt(at) == '#';
    }

    public String word() {
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

    public String op() {
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
    public void items(List<AttributeItem> into) {
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

    /** Every item of {@code text}; errors name {@code what}. */
    public static List<AttributeItem> parse(String text, String what) {
        List<AttributeItem> items = new java.util.ArrayList<>();
        try {
            new ItemParser(text, 1).items(items);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(what + ": " + e.getMessage().replaceFirst("^line 1: ", ""), e);
        }
        return List.copyOf(items);
    }
}
