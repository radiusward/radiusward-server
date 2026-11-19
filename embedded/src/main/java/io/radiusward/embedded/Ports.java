/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import java.net.DatagramSocket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Each member's six UDP ports (ingress, consensus, log, catch-up, archive and its replication) need a free range: a
 * base below the ephemeral ports (Linux from 32768, macOS from 49152), where a port checked free is not taken by a
 * client's ephemeral socket before the member binds it. Bases handed out in this JVM are held until the member binds
 * them, so embedded servers started in parallel never share one.
 */
final class Ports {

    /** Bases handed out and not yet bound, with their number of members. */
    private static final Map<Integer, Integer> RESERVED = new HashMap<>();

    private Ports() {}

    /** A base where every member's ports ({@code base + 100 * member + 0..5}) are free. */
    static synchronized int reserveBase(int members) {
        for (int attempt = 0; attempt < 200; attempt++) {
            int base = 20_000 + ThreadLocalRandom.current().nextInt(120 - members) * 100; // below 32_000
            if (!overlaps(base, members) && free(base, members)) {
                RESERVED.put(base, members);
                return base;
            }
        }
        throw new IllegalStateException("no free range of ports for the member between 20000 and 32000");
    }

    static synchronized void release(int base) {
        RESERVED.remove(base);
    }

    private static boolean overlaps(int base, int members) {
        for (Map.Entry<Integer, Integer> r : RESERVED.entrySet()) {
            int start = r.getKey();
            int end = start + 100 * r.getValue();
            if (base < end && start < base + 100 * members) {
                return true;
            }
        }
        return false;
    }

    private static boolean free(int base, int members) {
        for (int m = 0; m < members; m++) {
            for (int o = 0; o < 6; o++) {
                try (DatagramSocket s = new DatagramSocket(base + 100 * m + o)) {
                    s.setReuseAddress(false);
                } catch (Exception e) {
                    return false;
                }
            }
        }
        return true;
    }
}
