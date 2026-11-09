/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.ldap;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.ItemParser;
import io.radiusward.auth.StoreContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Settings of an LDAP store or verifier ({@code auth.store.<name>.*} / {@code auth.verifier.<name>.*}).
 *
 * @param urls servers, tried in order ({@code url}, space or comma separated; {@code ldaps://} for TLS)
 * @param bindDn service account that searches ({@code bind.dn}); empty = anonymous
 * @param userFilter finds the user, {@code {0}} is the escaped user name
 * @param groupAttribute attribute listing the user's groups (DNs), {@code memberOf}
 * @param nestedGroups also groups of groups (Active Directory's in-chain matching rule) instead of the attribute
 * @param requireGroups the user must be in one of these groups, else {@code Auth-Type := Reject}; empty = no rule
 * @param policies check and reply items per group, in the order of their ids
 * @param check check items mapped from directory attributes (RADIUS name → LDAP attribute)
 * @param reply reply items mapped from directory attributes
 */
record LdapSettings(
        String name,
        String urls,
        String bindDn,
        String bindPassword,
        String baseDn,
        String userFilter,
        String groupAttribute,
        boolean nestedGroups,
        List<String> requireGroups,
        List<Policy> policies,
        Map<String, String> check,
        Map<String, String> reply,
        Duration timeout,
        int pool,
        Path tlsCa) {

    /** {@code policy.<id>.group}, {@code policy.<id>.check}, {@code policy.<id>.reply}. */
    record Policy(String group, List<AttributeItem> check, List<AttributeItem> reply) {}

    static LdapSettings from(StoreContext context, String prefix) {
        List<String> urlList = Arrays.stream(context.required("url").split("[,\\s]+"))
                .filter(u -> !u.isEmpty())
                .toList();
        String urls = String.join(" ", urlList);
        for (String url : urlList) {
            if (!url.startsWith("ldap://") && !url.startsWith("ldaps://")) {
                throw new IllegalArgumentException(prefix + "url: ldap:// or ldaps:// expected, got " + url);
            }
        }
        Map<String, String> settings = context.settings();
        TreeMap<String, String[]> byId = new TreeMap<>();
        Map<String, String> check = new TreeMap<>();
        Map<String, String> reply = new TreeMap<>();
        for (Map.Entry<String, String> e : settings.entrySet()) {
            String key = e.getKey();
            if (key.startsWith("policy.")) {
                String[] parts = key.split("\\.", 3);
                if (parts.length != 3 || !List.of("group", "check", "reply").contains(parts[2])) {
                    throw new IllegalArgumentException(prefix + key + ": expected policy.<id>.group|check|reply");
                }
                String[] policy = byId.computeIfAbsent(parts[1], id -> new String[3]);
                policy[List.of("group", "check", "reply").indexOf(parts[2])] = e.getValue();
            } else if (key.startsWith("check.")) {
                check.put(key.substring(6), e.getValue().trim());
            } else if (key.startsWith("reply.")) {
                reply.put(key.substring(6), e.getValue().trim());
            }
        }
        List<Policy> policies = new ArrayList<>();
        for (Map.Entry<String, String[]> p : byId.entrySet()) {
            String[] v = p.getValue();
            String where = prefix + "policy." + p.getKey();
            if (v[0] == null || v[0].isBlank()) {
                throw new IllegalArgumentException(where + ".group is required");
            }
            policies.add(new Policy(
                    v[0].trim(),
                    v[1] == null ? List.of() : ItemParser.parse(v[1], where + ".check"),
                    v[2] == null ? List.of() : ItemParser.parse(v[2], where + ".reply")));
        }
        String ca = context.setting("tls.ca", "");
        Path tlsCa = ca.isBlank() ? null : Path.of(ca);
        if (tlsCa != null && !Files.isReadable(tlsCa)) {
            throw new IllegalArgumentException(prefix + "tls.ca: cannot read " + tlsCa);
        }
        if (tlsCa != null && urlList.stream().anyMatch(u -> u.startsWith("ldap://"))) {
            throw new IllegalArgumentException(prefix + "tls.ca: applies to ldaps:// only, not to " + urls);
        }
        int pool = Integer.parseInt(context.setting("pool", Integer.toString(context.workers())));
        if (pool < 1) {
            throw new IllegalArgumentException(prefix + "pool: at least 1");
        }
        String filter = context.setting("user.filter", "(&(objectClass=user)(sAMAccountName={0}))");
        if (!filter.contains("{0}")) {
            throw new IllegalArgumentException(prefix + "user.filter: must contain {0} for the user name");
        }
        return new LdapSettings(
                context.name(),
                urls,
                context.setting("bind.dn", ""),
                context.setting("bind.password", ""),
                context.required("base.dn"),
                filter,
                context.setting("group.attribute", "memberOf"),
                Boolean.parseBoolean(context.setting("group.nested", "false")),
                commaList(context.setting("require.groups", "")),
                List.copyOf(policies),
                Map.copyOf(check),
                Map.copyOf(reply),
                context.duration("timeout", "1500ms"),
                pool,
                tlsCa);
    }

    /** Group names may contain spaces: only commas separate them. */
    private static List<String> commaList(String value) {
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
