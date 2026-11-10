/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

/**
 * Finds the RadSec home servers of a realm in DNS (RFC 7585, ADR 0037): NAPTR records of the realm with the service
 * {@code aaa+auth:radius.tls.tcp} and flag {@code s}, in order and preference, name SRV records; those give host and
 * port, by priority and weight. Blocking: called from a thread of its own, never from the auth thread.
 */
final class RealmDiscovery {

    static final String SERVICE = "aaa+auth:radius.tls.tcp";

    /** A home server found for a realm. */
    record Target(String host, int port) {}

    private final String dnsServer;

    /** @param dnsServer {@code host:port} of a DNS server, {@code null} for the system's */
    RealmDiscovery(String dnsServer) {
        this.dnsServer = dnsServer;
    }

    /** The realm's RadSec servers, best first; empty if it publishes none. */
    List<Target> lookup(String realm) throws NamingException {
        DirContext dns = context();
        try {
            List<String[]> naptrs = new ArrayList<>();
            for (String record : records(dns, realm, "NAPTR")) {
                String[] f = fields(record);
                if (f.length >= 6
                        && f[2].equalsIgnoreCase("s")
                        && f[3].toLowerCase(Locale.ROOT).equals(SERVICE)) {
                    naptrs.add(f);
                }
            }
            naptrs.sort(Comparator.<String[]>comparingInt(f -> Integer.parseInt(f[0]))
                    .thenComparingInt(f -> Integer.parseInt(f[1])));
            List<Target> targets = new ArrayList<>();
            for (String[] naptr : naptrs) {
                List<String[]> srvs = new ArrayList<>();
                for (String record : records(dns, trimDot(naptr[5]), "SRV")) {
                    String[] f = fields(record);
                    if (f.length >= 4) {
                        srvs.add(f);
                    }
                }
                srvs.sort(Comparator.<String[]>comparingInt(f -> Integer.parseInt(f[0]))
                        .thenComparingInt(f -> -Integer.parseInt(f[1])));
                for (String[] srv : srvs) {
                    targets.add(new Target(trimDot(srv[3]), Integer.parseInt(srv[2])));
                }
            }
            return targets;
        } finally {
            dns.close();
        }
    }

    /** The address of a host, from the same DNS server (A record), or the system's resolver without one. */
    java.net.InetAddress address(String host) throws NamingException, java.net.UnknownHostException {
        if (dnsServer == null) {
            return java.net.InetAddress.getByName(host);
        }
        DirContext dns = context();
        try {
            List<String> a = records(dns, host, "A");
            if (a.isEmpty()) {
                throw new java.net.UnknownHostException(host);
            }
            return java.net.InetAddress.getByName(a.get(0).trim());
        } finally {
            dns.close();
        }
    }

    private DirContext context() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(DirContext.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put(DirContext.PROVIDER_URL, dnsServer == null ? "dns:" : "dns://" + dnsServer);
        env.put("com.sun.jndi.dns.timeout.initial", "1000");
        env.put("com.sun.jndi.dns.timeout.retries", "2");
        return new InitialDirContext(env);
    }

    private static List<String> records(DirContext dns, String name, String type) throws NamingException {
        List<String> out = new ArrayList<>();
        try {
            Attributes attributes = dns.getAttributes(name, new String[] {type});
            Attribute attribute = attributes.get(type);
            if (attribute != null) {
                NamingEnumeration<?> values = attribute.getAll();
                while (values.hasMore()) {
                    out.add(values.next().toString());
                }
            }
        } catch (javax.naming.NameNotFoundException e) {
            // no such name: no records
        }
        return out;
    }

    /** A record's fields, quoted strings unquoted: NAPTR {@code order pref "flags" "service" "regexp" replacement}. */
    static String[] fields(String record) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        boolean any = false;
        for (char c : record.toCharArray()) {
            if (c == '"') {
                quoted = !quoted;
                any = true;
            } else if (c == ' ' && !quoted) {
                if (any || field.length() > 0) {
                    fields.add(field.toString());
                }
                field.setLength(0);
                any = false;
            } else {
                field.append(c);
            }
        }
        if (any || field.length() > 0) {
            fields.add(field.toString());
        }
        return fields.toArray(String[]::new);
    }

    private static String trimDot(String name) {
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }
}
