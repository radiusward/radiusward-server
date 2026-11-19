/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.radius.codec.RadiusCode;
import java.net.InetSocketAddress;

/** A CoA-Request or Disconnect-Request that {@link CoaListener} received and verified (RFC 5176). */
public final class CoaRequest extends ReceivedPacket {

    private final InetSocketAddress from;

    CoaRequest(byte[] bytes, InetSocketAddress from) {
        super(bytes);
        this.from = from;
    }

    public boolean isDisconnect() {
        return code() == RadiusCode.DISCONNECT_REQUEST;
    }

    public boolean isCoa() {
        return code() == RadiusCode.COA_REQUEST;
    }

    /** The RADIUS server that sent it. */
    public InetSocketAddress from() {
        return from;
    }
}
