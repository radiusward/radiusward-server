/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.management;

/** Result of a health or readiness check. */
public record Health(boolean up, String detail) {

    public static Health up(String detail) {
        return new Health(true, detail);
    }

    public static Health down(String detail) {
        return new Health(false, detail);
    }
}
