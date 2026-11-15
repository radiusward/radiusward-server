/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import java.net.DatagramSocket;
import java.net.ServerSocket;

/** Free ports for test clusters and servers, chosen below the operating systems' ephemeral port ranges. */
public final class Ports {

    private Ports() {}

    /**
     * A base port where every member's 6 UDP ports ({@code base + 100 * member + 0..5}) are free, below the ephemeral
     * port ranges (Linux from 32768, macOS from 49152): a port checked free there can still be taken by a client's
     * ephemeral socket (an Aeron egress or archive response channel) before the member binds it.
     */
    public static int freePortBase(int members) {
        for (int attempt = 0; attempt < 100; attempt++) {
            int base = 20_000 + (int) (Math.random() * 120) * 100; // highest port 32_205
            if (allFree(base, members)) {
                return base;
            }
        }
        throw new IllegalStateException("no free port range");
    }

    /** A single port free for TCP and UDP, 10000–19999: below the ephemeral ranges and the cluster ports. */
    public static int freePort() {
        for (int attempt = 0; attempt < 200; attempt++) {
            int port = 10_000 + (int) (Math.random() * 10_000);
            try (ServerSocket tcp = new ServerSocket(port);
                    DatagramSocket udp = new DatagramSocket(port)) {
                if (tcp.getLocalPort() == port && udp.getLocalPort() == port) {
                    return port;
                }
            } catch (Exception e) {
                // taken, try another
            }
        }
        throw new IllegalStateException("no free port");
    }

    private static boolean allFree(int base, int members) {
        for (int i = 0; i < members; i++) {
            for (int o = 0; o < 6; o++) {
                try (DatagramSocket s = new DatagramSocket(base + 100 * i + o)) {
                    s.setReuseAddress(false);
                } catch (Exception e) {
                    return false;
                }
            }
        }
        return true;
    }
}
