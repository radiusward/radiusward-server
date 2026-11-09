/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.ldap;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Users from an LDAP directory ({@code auth.store.<name>.type = ldap}), Active Directory in particular (ADR 0025).
 * The directory holds no password radiusward can read: a credential verifier checks it ({@code
 * auth.store.<name>.verifier}). The store supplies:
 *
 * <ul>
 *   <li>groups, from {@code memberOf} or — {@code group.nested} — every group the user is in through other groups;
 *   <li>{@code require.groups}: outside all of them, {@code Auth-Type := Reject};
 *   <li>policies per group ({@code policy.<id>.group}, {@code .check}, {@code .reply}, users-file item syntax);
 *   <li>items mapped from attributes ({@code check.<RADIUS attribute>}, {@code reply.<RADIUS attribute>} = LDAP
 *       attribute);
 *   <li>Active Directory account state: disabled ({@code userAccountControl}) or expired ({@code accountExpires})
 *       accounts get {@code Auth-Type := Reject}.
 * </ul>
 */
final class LdapStore implements IdentityStore {

    static final String IN_CHAIN = "1.2.840.113556.1.4.1941"; // LDAP_MATCHING_RULE_IN_CHAIN
    private static final int ACCOUNT_DISABLED = 0x2;
    private static final long NEVER = Long.MAX_VALUE;
    private static final long FILETIME_TO_EPOCH_MS = 11_644_473_600_000L;

    private final LdapSettings settings;
    private final Directory directory;
    private final LongSupplier clock;
    private final String[] attributes;

    LdapStore(StoreContext context) {
        this(LdapSettings.from(context, "auth.store." + context.name() + "."), System::currentTimeMillis);
    }

    LdapStore(LdapSettings settings, LongSupplier clock) {
        this.settings = settings;
        this.directory = new Directory(settings);
        this.clock = clock;
        Set<String> wanted = new LinkedHashSet<>(List.of("userAccountControl", "accountExpires"));
        if (!settings.nestedGroups()) {
            wanted.add(settings.groupAttribute());
        }
        wanted.addAll(settings.check().values());
        wanted.addAll(settings.reply().values());
        this.attributes = wanted.toArray(String[]::new);
    }

    @Override
    public Optional<UserRecord> lookup(String userName) throws StoreUnavailableException {
        List<Directory.Entry> found =
                directory.search(settings.userFilter(), new Object[] {settings.lookupName(userName)}, attributes, 2);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        if (found.size() > 1) {
            throw new StoreUnavailableException(
                    "ldap store " + settings.name() + ": user.filter finds more than one entry for a user");
        }
        Directory.Entry entry = found.get(0);
        try {
            List<AttributeItem> check = new ArrayList<>();
            List<AttributeItem> reply = new ArrayList<>();
            if (!enabled(entry.attributes())) {
                check.add(new AttributeItem("Auth-Type", ":=", "Reject"));
            }
            List<String> groups = groups(entry);
            if (!settings.requireGroups().isEmpty()
                    && settings.requireGroups().stream().noneMatch(r -> contains(groups, r))) {
                check.add(new AttributeItem("Auth-Type", ":=", "Reject"));
            }
            map(settings.check(), entry.attributes(), ":=", check);
            map(settings.reply(), entry.attributes(), "=", reply);
            List<UserRecord.Group> policies = new ArrayList<>();
            for (LdapSettings.Policy p : settings.policies()) {
                if (contains(groups, p.group())) {
                    policies.add(new UserRecord.Group(p.group(), p.check(), p.reply()));
                }
            }
            return Optional.of(new UserRecord(userName, check, reply, policies));
        } catch (NamingException e) {
            throw new StoreUnavailableException("ldap store " + settings.name() + ": " + e.getMessage());
        }
    }

    /** Active Directory: not disabled and not expired; entries without these attributes are enabled. */
    private boolean enabled(Attributes a) throws NamingException {
        Attribute control = a.get("userAccountControl");
        if (control != null && (Long.parseLong(control.get().toString()) & ACCOUNT_DISABLED) != 0) {
            return false;
        }
        Attribute expires = a.get("accountExpires");
        if (expires != null) {
            long filetime = Long.parseLong(expires.get().toString());
            if (filetime != 0 && filetime != NEVER) {
                return filetime / 10_000 - FILETIME_TO_EPOCH_MS > clock.getAsLong();
            }
        }
        return true;
    }

    /** Names (first RDN value, e.g. the CN) of the user's groups. */
    private List<String> groups(Directory.Entry entry) throws NamingException, StoreUnavailableException {
        List<String> names = new ArrayList<>();
        if (settings.nestedGroups()) {
            for (Directory.Entry g : directory.search(
                    "(member:" + IN_CHAIN + ":={0})", new Object[] {entry.dn()}, new String[] {"cn"}, 0)) {
                names.add(firstRdn(g.dn()));
            }
            return names;
        }
        Attribute memberOf = entry.attributes().get(settings.groupAttribute());
        if (memberOf != null) {
            NamingEnumeration<?> values = memberOf.getAll();
            while (values.hasMore()) {
                names.add(firstRdn(values.next().toString()));
            }
        }
        return names;
    }

    private static String firstRdn(String dn) throws NamingException {
        List<Rdn> rdns = new LdapName(dn).getRdns();
        return rdns.isEmpty() ? dn : rdns.get(rdns.size() - 1).getValue().toString();
    }

    private static boolean contains(List<String> groups, String group) {
        return groups.stream().anyMatch(g -> g.equalsIgnoreCase(group));
    }

    /** One item per value; a second value of the same attribute adds ({@code +=}). */
    private static void map(Map<String, String> mapping, Attributes a, String op, List<AttributeItem> into)
            throws NamingException {
        for (Map.Entry<String, String> m : mapping.entrySet()) {
            Attribute attribute = a.get(m.getValue());
            if (attribute == null) {
                continue;
            }
            NamingEnumeration<?> values = attribute.getAll();
            boolean first = true;
            while (values.hasMore()) {
                Object v = values.next();
                into.add(new AttributeItem(m.getKey(), first ? op : "+=", v.toString()));
                first = false;
            }
        }
    }

    Directory directory() {
        return directory;
    }

    @Override
    public void close() {
        directory.close();
    }
}
