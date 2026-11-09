/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Hashtable;
import java.util.List;
import java.util.function.LongSupplier;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.InitialDirContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The domain controllers to try, in order: the configured {@code server} list, or — without one — the DNS SRV records
 * {@code _ldap._tcp.dc._msdcs.<dns.domain>} as Windows clients find them (lower priority first, then higher weight),
 * looked up again every {@code dns.refresh}. A failed lookup keeps the last good list.
 */
final class DomainControllers {

    private static final Logger LOG = LogManager.getLogger(DomainControllers.class);

    /** One SRV record. */
    record Srv(int priority, int weight, int port, String target) {}

    /** Looks up the SRV records of a name. */
    @FunctionalInterface
    interface Resolver {
        List<Srv> srv(String name) throws NamingException;
    }

    private final List<String> fixed;
    private final String dnsDomain;
    private final Resolver resolver;
    private final long refreshMillis;
    private final LongSupplier clock;
    private volatile List<String> found = List.of();
    private volatile long nextLookup;

    DomainControllers(List<String> fixed, String dnsDomain, Resolver resolver, long refreshMillis, LongSupplier clock) {
        this.fixed = List.copyOf(fixed);
        this.dnsDomain = dnsDomain;
        this.resolver = resolver;
        this.refreshMillis = refreshMillis;
        this.clock = clock;
    }

    static DomainControllers of(NetlogonSettings settings) {
        return new DomainControllers(
                settings.servers(),
                settings.dnsDomain(),
                jndi(settings.dnsServer()),
                settings.dnsRefresh().toMillis(),
                System::currentTimeMillis);
    }

    /** Host names in the order to try them; empty if DNS knows none (yet). */
    List<String> current() {
        if (!fixed.isEmpty()) {
            return fixed;
        }
        long now = clock.getAsLong();
        if (now - nextLookup >= 0) {
            refresh(now);
        }
        return found;
    }

    /** After every server failed: look DNS up again at the next call. */
    void failed() {
        nextLookup = clock.getAsLong();
    }

    private synchronized void refresh(long now) {
        if (now - nextLookup < 0) {
            return; // another thread just did
        }
        nextLookup = now + refreshMillis;
        String name = "_ldap._tcp.dc._msdcs." + dnsDomain;
        try {
            List<String> hosts = order(resolver.srv(name));
            if (hosts.isEmpty()) {
                LOG.warn("no domain controller in DNS for {}; keeping {}", name, found);
            } else {
                found = hosts;
            }
        } catch (NamingException e) {
            LOG.warn("DNS lookup of {} failed, keeping {}: {}", name, found, e.getMessage());
        }
    }

    /** Lower priority first, then higher weight; RFC 2782's "." target (no service) dropped. */
    static List<String> order(List<Srv> records) {
        List<Srv> sorted = new ArrayList<>(records);
        sorted.removeIf(r -> r.target().isEmpty() || r.target().equals("."));
        sorted.sort(Comparator.comparingInt(Srv::priority)
                .thenComparing(Comparator.comparingInt(Srv::weight).reversed()));
        List<String> hosts = new ArrayList<>();
        for (Srv r : sorted) {
            String host = r.target().endsWith(".")
                    ? r.target().substring(0, r.target().length() - 1)
                    : r.target();
            if (!hosts.contains(host)) {
                hosts.add(host);
            }
        }
        return List.copyOf(hosts);
    }

    /** SRV look-ups with the JDK's DNS provider; {@code dnsServer} empty = the system's resolvers. */
    static Resolver jndi(String dnsServer) {
        return name -> {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("java.naming.provider.url", dnsServer.isEmpty() ? "dns:" : "dns://" + dnsServer);
            env.put("com.sun.jndi.dns.timeout.initial", "1000");
            env.put("com.sun.jndi.dns.timeout.retries", "2");
            InitialDirContext dns = new InitialDirContext(env);
            try {
                Attribute srv = dns.getAttributes(name, new String[] {"SRV"}).get("SRV");
                List<Srv> records = new ArrayList<>();
                if (srv != null) {
                    NamingEnumeration<?> values = srv.getAll();
                    while (values.hasMore()) {
                        String[] f = values.next().toString().trim().split("\\s+");
                        if (f.length == 4) {
                            records.add(new Srv(
                                    Integer.parseInt(f[0]), Integer.parseInt(f[1]), Integer.parseInt(f[2]), f[3]));
                        }
                    }
                }
                return records;
            } finally {
                dns.close();
            }
        };
    }
}
