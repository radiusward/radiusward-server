/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import java.net.DatagramSocket;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * The member's six UDP ports (ingress, consensus, log, catch-up, archive and its replication) need a free range: a
 * base below the ephemeral ports (Linux from 32768, macOS from 49152), where a port checked free is not taken by a
 * client's ephemeral socket before the member binds it. Bases handed out in this JVM are held until the member binds
 * them, so embedded servers started in parallel never share one.
 */
final class Ports {

    private static final Set<Integer> RESERVED = new HashSet<>();

    private Ports() {}

    static synchronized int reserveBase() {
        for (int attempt = 0; attempt < 200; attempt++) {
            int base = 20_000 + ThreadLocalRandom.current().nextInt(120) * 100; // highest port 31_905
            if (!RESERVED.contains(base) && free(base)) {
                RESERVED.add(base);
                return base;
            }
        }
        throw new IllegalStateException("no free range of ports for the member between 20000 and 32000");
    }

    static synchronized void release(int base) {
        RESERVED.remove(base);
    }

    private static boolean free(int base) {
        for (int o = 0; o < 6; o++) {
            try (DatagramSocket s = new DatagramSocket(base + o)) {
                s.setReuseAddress(false);
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }
}
