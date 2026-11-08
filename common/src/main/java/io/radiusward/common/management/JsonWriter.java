/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.management;

/**
 * Minimal JSON object writer for management responses (no JSON library). Not thread-safe; create one per
 * response. Runs on the management thread, never on the hot path.
 */
public final class JsonWriter {

    private final StringBuilder out = new StringBuilder(256);
    private boolean first = true;

    public JsonWriter() {
        out.append('{');
    }

    public JsonWriter field(String name, long value) {
        name(name);
        out.append(value);
        return this;
    }

    public JsonWriter field(String name, boolean value) {
        name(name);
        out.append(value);
        return this;
    }

    public JsonWriter field(String name, String value) {
        name(name);
        if (value == null) {
            out.append("null");
        } else {
            string(value);
        }
        return this;
    }

    /** Starts a nested object; close it with {@link #end()}. */
    public JsonWriter object(String name) {
        name(name);
        out.append('{');
        first = true;
        return this;
    }

    public JsonWriter end() {
        out.append('}');
        first = false;
        return this;
    }

    /** Closes the top-level object and returns the JSON text. */
    public String finish() {
        return out.append('}').toString();
    }

    private void name(String name) {
        if (!first) {
            out.append(',');
        }
        first = false;
        string(name);
        out.append(':');
    }

    private void string(String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
