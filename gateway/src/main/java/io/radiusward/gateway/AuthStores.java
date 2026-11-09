/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.IdentityStoreProvider;
import io.radiusward.auth.StoreContext;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.stream.Stream;

/**
 * The identity stores of a gateway ({@code auth.stores}, {@code auth.store.<name>.*}), created through
 * {@link IdentityStoreProvider}s on the class path and in {@code auth.plugins.dir}, and which of them answer each NAS
 * entry ({@code nas.<name>.auth.stores}, default all, in order).
 *
 * @param chap stores where CHAP may use the cleartext password ({@code auth.store.<name>.chap = true})
 * @param bcryptMaxCost the highest bcrypt cost verified ({@code auth.bcrypt.max.cost}); a stored hash above it is
 *     rejected instead of occupying a worker for seconds
 */
record AuthStores(
        Map<String, IdentityStore> stores,
        List<String> order,
        Map<String, List<String>> perNas,
        Map<String, Boolean> chap,
        Duration cacheTtl,
        int cacheMax,
        int bcryptMaxCost)
        implements AutoCloseable {

    static AuthStores from(Config config, int workers) {
        List<String> names = config.list("auth.stores", List.of());
        if (names.isEmpty()) {
            throw new ConfigException("auth.stores: name at least one identity store (auth.store.<name>.type)");
        }
        Map<String, IdentityStoreProvider> providers = providers(config);
        Map<String, IdentityStore> stores = new LinkedHashMap<>();
        Map<String, Boolean> chap = new HashMap<>();
        try {
            for (String name : names) {
                String prefix = "auth.store." + name + ".";
                String type = config.string(prefix + "type");
                IdentityStoreProvider provider = providers.get(type);
                if (provider == null) {
                    throw new ConfigException(prefix + "type: no identity store of type " + type + " (known: "
                            + providers.keySet() + ")");
                }
                Map<String, String> settings = new HashMap<>(config.subset(prefix));
                chap.put(name, Boolean.parseBoolean(settings.getOrDefault("chap", "false")));
                try {
                    stores.put(name, provider.create(new StoreContext(name, settings, workers)));
                } catch (IllegalArgumentException e) {
                    throw new ConfigException(e.getMessage(), e);
                }
            }
        } catch (RuntimeException e) {
            stores.values().forEach(IdentityStore::close);
            throw e;
        }
        Map<String, List<String>> perNas = new HashMap<>();
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
                bcryptMaxCost(config));
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
        Map<String, IdentityStoreProvider> providers = new HashMap<>();
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
