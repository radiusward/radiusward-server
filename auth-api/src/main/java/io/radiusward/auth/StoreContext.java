/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

import java.util.Map;

/**
 * What a store is created with.
 *
 * @param name the store's name ({@code auth.store.<name>.*})
 * @param settings its settings without the prefix
 * @param workers the gateway's worker threads ({@code gateway.auth.workers}): a store's connection pool rarely needs
 *     more
 */
public record StoreContext(String name, Map<String, String> settings, int workers) {

    public StoreContext {
        settings = Map.copyOf(settings);
    }

    public String setting(String key, String fallback) {
        return settings.getOrDefault(key, fallback);
    }

    /** A duration such as {@code 1500ms}, {@code 5s}, {@code 2m}, {@code 1h}. */
    public java.time.Duration duration(String key, String fallback) {
        String text = setting(key, fallback).trim().toLowerCase(java.util.Locale.ROOT);
        try {
            if (text.endsWith("ms")) {
                return java.time.Duration.ofMillis(Long.parseLong(text.substring(0, text.length() - 2)));
            }
            long n = Long.parseLong(text.substring(0, text.length() - 1));
            return switch (text.charAt(text.length() - 1)) {
                case 's' -> java.time.Duration.ofSeconds(n);
                case 'm' -> java.time.Duration.ofMinutes(n);
                case 'h' -> java.time.Duration.ofHours(n);
                default -> throw new NumberFormatException();
            };
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(
                    "auth.store." + name + "." + key + ": expected a duration like 1500ms, 5s or 2m, got " + text);
        }
    }

    public String required(String key) {
        String value = settings.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("auth.store." + name + "." + key + " is required");
        }
        return value;
    }
}
