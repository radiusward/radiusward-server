/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.IdentityStoreProvider;
import io.radiusward.auth.StoreContext;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.VendorDef;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.stream.Stream;
import org.agrona.collections.IntHashSet;
import org.agrona.collections.Object2ObjectHashMap;

/**
 * The identity stores of a gateway ({@code auth.stores}, {@code auth.store.<name>.*}), created through
 * {@link IdentityStoreProvider}s on the class path and in {@code auth.plugins.dir}, and which of them answer each NAS
 * entry ({@code nas.<name>.auth.stores}, default all, in order).
 *
 * @param chap stores where CHAP may use the cleartext password ({@code auth.store.<name>.chap = true})
 * @param mschap stores where MS-CHAP may derive the NT hash from the cleartext password
 *     ({@code auth.store.<name>.mschap = true}); {@code NT-Password} needs no opt-in
 * @param bcryptMaxCost the highest bcrypt cost verified ({@code auth.bcrypt.max.cost}); a stored hash above it is
 *     rejected instead of occupying a worker for seconds
 * @param replyVendors per NAS entry, the vendors whose attributes its replies may carry ({@code nas.<name>.reply.vendors},
 *     by default from {@code nas.<name>.vendor}); a NAS entry without one gets every reply item
 */
record AuthStores(
        Map<String, IdentityStore> stores,
        List<String> order,
        Map<String, List<String>> perNas,
        Map<String, Boolean> chap,
        Duration cacheTtl,
        int cacheMax,
        int bcryptMaxCost,
        Map<String, IntHashSet> replyVendors,
        Map<String, Boolean> mschap)
        implements AutoCloseable {

    /** Vendors whose attributes a NAS of this vendor also understands (Juniper's E-series / ERX attributes). */
    private static final Map<String, List<Integer>> RELATED = Map.of("juniper", List.of(4874));

    static AuthStores from(Config config, int workers) {
        return from(config, workers, null);
    }

    /**
     * @param dictionary checks reply items where a store reads its users up front, and resolves vendor names;
     *     {@code null} skips both (tests)
     */
    static AuthStores from(Config config, int workers, Dictionary dictionary) {
        List<String> names = config.list("auth.stores", List.of());
        if (names.isEmpty()) {
            throw new ConfigException("auth.stores: name at least one identity store (auth.store.<name>.type)");
        }
        Map<String, IdentityStoreProvider> providers = providers(config);
        Map<String, IdentityStore> stores = new Object2ObjectHashMap<>();
        Map<String, Boolean> chap = new Object2ObjectHashMap<>();
        Map<String, Boolean> mschap = new Object2ObjectHashMap<>();
        try {
            for (String name : names) {
                String prefix = "auth.store." + name + ".";
                String type = config.string(prefix + "type");
                IdentityStoreProvider provider = providers.get(type);
                if (provider == null) {
                    throw new ConfigException(prefix + "type: no identity store of type " + type + " (known: "
                            + providers.keySet() + ")");
                }
                Map<String, String> settings = new Object2ObjectHashMap<>();
                settings.putAll(config.subset(prefix));
                chap.put(name, Boolean.parseBoolean(settings.getOrDefault("chap", "false")));
                mschap.put(name, Boolean.parseBoolean(settings.getOrDefault("mschap", "false")));
                try {
                    stores.put(
                            name,
                            provider.create(
                                    new StoreContext(name, settings, workers, item -> replyProblem(dictionary, item))));
                } catch (IllegalArgumentException e) {
                    throw new ConfigException(e.getMessage(), e);
                }
            }
        } catch (RuntimeException e) {
            stores.values().forEach(IdentityStore::close);
            throw e;
        }
        Map<String, List<String>> perNas = new Object2ObjectHashMap<>();
        for (String nas : config.names("nas")) {
            List<String> list = config.list("nas." + nas + ".auth.stores", List.of());
            for (String s : list) {
                if (!stores.containsKey(s)) {
                    throw new ConfigException("nas." + nas + ".auth.stores: unknown store " + s);
                }
            }
            if (!list.isEmpty()) {
                perNas.put(nas, List.copyOf(list));
            }
        }
        return new AuthStores(
                stores,
                List.copyOf(names),
                perNas,
                chap,
                config.duration("auth.cache.ttl", Duration.ofSeconds(5)),
                config.integer("auth.cache.max", 100_000),
                bcryptMaxCost(config),
                dictionary == null ? Map.of() : replyVendors(config, dictionary),
                mschap);
    }

    /** Why {@code item} cannot be sent in a reply, or {@code null}. */
    static String replyProblem(Dictionary dictionary, AttributeItem item) {
        if (dictionary == null) {
            return null;
        }
        AttributeDef def = dictionary.find(item.attribute());
        if (def == null) {
            return "reply item " + item.attribute() + " is not in the dictionary";
        }
        try {
            AttributeText.encode(def, item.value());
            return null;
        } catch (IllegalArgumentException e) {
            return "reply item " + item.attribute() + ": " + e.getMessage();
        }
    }

    private static Map<String, IntHashSet> replyVendors(Config config, Dictionary dictionary) {
        Map<String, IntHashSet> result = new Object2ObjectHashMap<>();
        for (String nas : config.names("nas")) {
            String key = "nas." + nas + ".reply.vendors";
            List<String> names = config.list(key, List.of());
            IntHashSet ids = new IntHashSet();
            if (names.isEmpty()) {
                String vendor =
                        config.string("nas." + nas + ".vendor", "default").toLowerCase(Locale.ROOT);
                VendorDef def = dictionary.vendor(vendor);
                if (def == null) {
                    continue; // "default" or a profile without dictionary vendor: every item is sent
                }
                ids.add(def.id());
                RELATED.getOrDefault(vendor, List.of()).forEach(ids::add);
            } else {
                if (names.stream().anyMatch(n -> n.equalsIgnoreCase("all"))) {
                    continue;
                }
                for (String name : names) {
                    VendorDef def = dictionary.vendor(name);
                    if (def == null && !name.equalsIgnoreCase("none")) {
                        throw new ConfigException(
                                key + ": unknown vendor " + name + " (a dictionary VENDOR name, all or" + " none)");
                    }
                    if (def != null) {
                        ids.add(def.id());
                    }
                }
            }
            result.put(nas, ids);
        }
        return result;
    }

    private static int bcryptMaxCost(Config config) {
        int cost = config.integer("auth.bcrypt.max.cost", 14);
        if (cost < BCrypt.MIN_COST || cost > BCrypt.MAX_COST) {
            throw new ConfigException("auth.bcrypt.max.cost: between " + BCrypt.MIN_COST + " and " + BCrypt.MAX_COST);
        }
        return cost;
    }

    /** The stores asked for a request from NAS entry {@code nas}, in order. */
    List<String> storesFor(String nas) {
        return perNas.getOrDefault(nas, order);
    }

    private static Map<String, IdentityStoreProvider> providers(Config config) {
        Map<String, IdentityStoreProvider> providers = new Object2ObjectHashMap<>();
        ServiceLoader.load(IdentityStoreProvider.class).forEach(p -> providers.put(p.type(), p));
        Path dir = Path.of(config.string("auth.plugins.dir", "/opt/radiusward/plugins"));
        if (Files.isDirectory(dir)) {
            List<URL> jars = new ArrayList<>();
            try (Stream<Path> files = Files.list(dir)) {
                for (Path jar : files.filter(f -> f.toString().endsWith(".jar")).toList()) {
                    jars.add(jar.toUri().toURL());
                }
            } catch (IOException e) {
                throw new ConfigException("auth.plugins.dir: cannot read " + dir, e);
            }
            ClassLoader loader = new URLClassLoader(jars.toArray(URL[]::new), AuthStores.class.getClassLoader());
            ServiceLoader.load(IdentityStoreProvider.class, loader).forEach(p -> providers.putIfAbsent(p.type(), p));
        }
        return providers;
    }

    @Override
    public void close() {
        stores.values().forEach(IdentityStore::close);
    }
}
