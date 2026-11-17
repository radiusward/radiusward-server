/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.LongSupplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The home servers of realms found in DNS (RFC 7585, ADR 0038): NAPTR, SRV and addresses, looked up on a thread of
 * their own so the proxy never waits, kept for {@code proxy.discovery.ttl}, a failure or no answer for the negative
 * TTL. The proxy asks from its thread; until a lookup is done it gets {@code null} and drops the request, whose
 * retransmission then finds the result.
 */
final class DiscoveredRealms implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(DiscoveredRealms.class);

    /** DNS: the RadSec targets of a realm and their addresses ({@link RealmDiscovery}). */
    interface Resolver {
        List<RealmDiscovery.Target> lookup(String realm) throws Exception;

        InetAddress address(String host) throws Exception;
    }

    /** The proxy's index of a discovered home server, created on first use. */
    interface Homes {
        int indexOf(RealmDiscovery.Target target, InetAddress address);
    }

    private record Found(List<RealmDiscovery.Target> targets, List<InetAddress> addresses, long expires) {}

    private final ProxyConfig.Discovery settings;
    private final Resolver resolver;
    private final ExecutorService lookups;
    private final LongSupplier nanoClock;
    private final ConcurrentHashMap<String, Found> found = new ConcurrentHashMap<>();
    private final Set<String> looking = ConcurrentHashMap.newKeySet();
    // the proxy thread's own view: the pools it built from found, and until when they hold
    private final Map<String, int[]> pools = new HashMap<>();
    private final Map<String, Long> until = new HashMap<>();

    DiscoveredRealms(
            ProxyConfig.Discovery settings, Resolver resolver, ExecutorService lookups, LongSupplier nanoClock) {
        this.settings = settings;
        this.resolver = resolver;
        this.lookups = lookups;
        this.nanoClock = nanoClock;
    }

    /** Discovery as configured: the DNS server of {@code settings}, one daemon thread. */
    static DiscoveredRealms of(ProxyConfig.Discovery settings) {
        RealmDiscovery dns = new RealmDiscovery(settings.dnsServer());
        ExecutorService thread = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "realm-discovery");
            t.setDaemon(true);
            return t;
        });
        return new DiscoveredRealms(settings, dns, thread, System::nanoTime);
    }

    /**
     * The home servers of {@code realm}, by the proxy's index; {@code null} while it is being looked up. Called by the
     * proxy's thread only.
     */
    int[] pool(String realm, long now, Homes homes) {
        Long valid = until.get(realm);
        if (valid != null && now - valid < 0) {
            return pools.get(realm);
        }
        Found f = found.get(realm);
        if (f != null && now - f.expires() < 0) {
            int[] pool = new int[f.targets().size()];
            for (int i = 0; i < pool.length; i++) {
                pool[i] = homes.indexOf(f.targets().get(i), f.addresses().get(i));
            }
            pools.put(realm, pool);
            until.put(realm, f.expires());
            return pool;
        }
        if (looking.add(realm)) {
            lookups.execute(() -> lookup(realm));
        }
        return null;
    }

    /** On the lookup thread: NAPTR, SRV, addresses; kept for the TTL, a failure for the negative TTL. */
    private void lookup(String realm) {
        try {
            List<RealmDiscovery.Target> targets = resolver.lookup(realm);
            List<InetAddress> addresses = new ArrayList<>();
            for (RealmDiscovery.Target t : targets) {
                addresses.add(resolver.address(t.host()));
            }
            long ttl = (targets.isEmpty() ? settings.negativeTtl() : settings.ttl()).toNanos();
            found.put(realm, new Found(targets, addresses, nanoClock.getAsLong() + ttl));
            LOG.info("realm {}: {} RadSec home server(s) from DNS {}", realm, targets.size(), targets);
        } catch (Exception e) {
            found.put(
                    realm,
                    new Found(
                            List.of(),
                            List.of(),
                            nanoClock.getAsLong() + settings.negativeTtl().toNanos()));
            LOG.warn("realm {}: DNS discovery failed: {}", realm, e.toString());
        } finally {
            looking.remove(realm);
        }
    }

    @Override
    public void close() {
        lookups.shutdownNow();
    }
}
