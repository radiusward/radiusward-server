/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

/**
 * Simultaneous use, as an {@link AccessHandler} sees it (ADR 0023): asks the cluster whether a user may bring another
 * device online. One instance per worker ({@link AccessContext#sessionLimits()}); it waits for the cluster's answer,
 * which comes after the reservation is committed.
 */
public interface SessionLimits {

    /** Below the limit; the place is held until the device's Accounting-Start or the reservation's expiry. */
    int GRANTED = 0;

    /** As many devices online or reserved as the limit allows. */
    int DENIED = 1;

    /** The cluster does not count users yet (state version 6 not active): the limit cannot be applied. */
    int UNSUPPORTED = 2;

    /** No answer in time, the cluster unreachable or full: the request must not be answered. */
    int UNAVAILABLE = 3;

    /** Without a cluster (tests): every request is {@link #UNAVAILABLE}. */
    SessionLimits NONE = (userKey, deviceKey, maxDevices) -> UNAVAILABLE;

    /**
     * @param userKey {@link UserKeys#user}
     * @param deviceKey {@link UserKeys#device}, 0 if the request has no Calling-Station-Id
     * @param maxDevices the user's {@code Simultaneous-Use}
     */
    int reserve(long userKey, long deviceKey, int maxDevices);
}
