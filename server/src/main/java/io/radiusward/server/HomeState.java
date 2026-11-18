/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicLongArray;

/** A home server: its identifiers in flight, its health, its counters. Used by the proxy's thread; counters and liveness are read by metrics. */
final class HomeState {
    final int index; // in the proxy's list of home servers
    final ProxyConfig.Home config;
    final InetSocketAddress address;
    final int[] slotById = new int[256];
    final byte[] statusAuthenticator = new byte[16];
    final AtomicLongArray counts = new AtomicLongArray(Proxy.Counter.values().length);
    int nextId;
    volatile boolean alive = true;
    long waitingSince; // first request sent since the last answer; 0 while answered
    long nextStatus;
    int statusId = -1;
    final HomeConnection tls; // RadSec, TCP or DTLS home servers (ADR 0055); null over UDP

    HomeState(int index, ProxyConfig.Home config) {
        this(
                index,
                config,
                switch (config.transport()) {
                    case TLS -> TlsClient.context(config.certificate(), config.key(), config.ca());
                    case DTLS -> TlsClient.context(config.certificate(), config.key(), config.ca(), "DTLS");
                    default -> null;
                });
    }

    HomeState(int index, ProxyConfig.Home config, javax.net.ssl.SSLContext context) {
        this.index = index;
        this.config = config;
        this.address = new InetSocketAddress(config.address(), config.port());
        String serverName = config.serverName() != null ? config.serverName() : config.host();
        this.tls = switch (config.transport()) {
            case TLS -> new TlsClient(context, serverName, address);
            case DTLS -> new HomeDtlsClient(context, serverName, address);
            case TCP -> new HomeTcpClient(address);
            case UDP -> null;
        };
        java.util.Arrays.fill(slotById, -1);
    }

    int allocateId(int slot) {
        for (int n = 0; n < 256; n++) {
            int id = (nextId + n) & 0xFF;
            if (slotById[id] == -1) {
                slotById[id] = slot;
                nextId = (id + 1) & 0xFF;
                return id;
            }
        }
        return -1;
    }
}
