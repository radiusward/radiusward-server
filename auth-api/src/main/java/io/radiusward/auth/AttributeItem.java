/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

/**
 * One {@code attribute op value} row ({@code radcheck}, {@code radreply}, a users-file item).
 *
 * @param attribute dictionary name, e.g. {@code Session-Timeout}, {@code Cisco-AVPair}
 * @param op {@code :=}, {@code =}, {@code ==}, {@code +=}, {@code !=}, {@code =~}, {@code !~}, …
 * @param value the value as text, as the store holds it
 */
public record AttributeItem(String attribute, String op, String value) {

    @Override
    public String toString() {
        // never print values: they may be passwords
        return attribute + " " + op + " …";
    }
}
