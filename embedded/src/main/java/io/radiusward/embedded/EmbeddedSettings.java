/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.CredentialVerifierProvider;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.IdentityStoreProvider;
import io.radiusward.auth.UserRecord;
import io.radiusward.export.SinkProvider;
import io.radiusward.server.AuthPlugins;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * What an {@link EmbeddedRadiusward.Builder} turns into: the settings the members and RADIUS servers start with (the
 * embedded defaults, then the builder's methods, then its {@code setting(...)}s), and the developer's stores, verifiers
 * and sinks as providers given in code.
 */
final class EmbeddedSettings {

    private EmbeddedSettings() {}

    /** The embedded defaults, then what the builder's methods say, then its {@code setting(...)}s. */
    static Map<String, String> values(EmbeddedRadiusward.Builder b, Path dir, int basePort) {
        Map<String, String> v = new LinkedHashMap<>();
        v.put("profile", "small");
        v.put("cluster.node.id", "0");
        v.put("cluster.members", String.join(", ", java.util.Collections.nCopies(b.members, "localhost")));
        v.put("cluster.base.port", Integer.toString(basePort));
        v.put("cluster.data.dir", dir.resolve("data").toString());
        v.put("cluster.aeron.dir", dir.resolve("aeron/member-0").toString());
        v.put("cluster.disk.min.free", "0");
        v.put("archive.file.sync.level", "0"); // nothing to survive: no fsync
        v.put("archive.segment.length", "8m"); // instead of 128 MB preallocated on disk
        v.put("log.purge.interval", "1s"); // the b.members report their state version this often
        v.put("service.max.sessions", "10000");
        v.put("server.id", "1");
        v.put("server.listen.host", "127.0.0.1");
        v.put("server.listen.port", Integer.toString(b.accountingPort));
        v.put("server.aeron.dir", dir.resolve("aeron/server-1").toString());
        v.put("server.pending.capacity", "1024");
        v.put("server.auth.enabled", "true");
        v.put("server.auth.port", Integer.toString(b.authPort));
        v.put("server.auth.workers", "2");
        v.put("auth.reject.delay", "0s"); // tests should not wait a second for every reject
        v.put("auth.plugins.dir", dir.resolve("plugins").toString());
        v.put("export.plugins.dir", dir.resolve("plugins").toString());
        v.put("dictionary.dir", dir.resolve("dictionary.d").toString());
        v.put("coa.enabled", "true");
        if (b.nas.isEmpty()) {
            v.put("nas." + EmbeddedRadiusward.DEFAULT_NAS + ".address", "127.0.0.1");
            v.put("nas." + EmbeddedRadiusward.DEFAULT_NAS + ".secret", EmbeddedRadiusward.DEFAULT_SECRET);
        }
        b.nas.forEach((name, entry) -> {
            v.put("nas." + name + ".address", entry[0]);
            v.put("nas." + name + ".secret", entry[1]);
        });
        if (b.coaPort > 0) {
            for (String name :
                    b.nas.isEmpty() ? List.of(EmbeddedRadiusward.DEFAULT_NAS) : List.copyOf(b.nas.keySet())) {
                v.put("nas." + name + ".coa.port", Integer.toString(b.coaPort));
            }
        }
        if (!b.eap.isEmpty()) {
            v.put("auth.eap.methods", String.join(", ", b.eap));
            if (b.eap.contains("teap")) {
                v.put("auth.eap.teap.inner", "mschapv2, gtc, basic");
            }
        }
        v.putAll(b.generated);
        List<String> storeNames = new ArrayList<>();
        if (!b.users.isEmpty()) {
            storeNames.add("users");
            v.put("auth.store.users.type", "embedded-users");
            v.put("auth.store.users.chap", "true");
            v.put("auth.store.users.mschap", "true");
        }
        for (int i = 0; i < b.stores.size(); i++) {
            String name = "store-" + (i + 1);
            storeNames.add(name);
            v.put("auth.store." + name + ".type", "embedded-" + name);
            if (!b.verifiers.isEmpty()) {
                v.put("auth.store." + name + ".verifier", "verifier");
            }
        }
        if (!b.verifiers.isEmpty()) {
            v.put("auth.verifiers", "verifier");
            v.put("auth.verifier.verifier.type", "embedded-verifier");
        }
        if (storeNames.isEmpty()) {
            storeNames.add("users"); // no b.users yet: every login is rejected, as by an empty b.users file
            v.put("auth.store.users.type", "embedded-users");
        }
        v.put("auth.stores", String.join(", ", storeNames));
        List<String> sinkNames = new ArrayList<>();
        sinkNames.add(RecordingSink.NAME);
        v.put("sink." + RecordingSink.NAME + ".type", RecordingSink.TYPE);
        v.put("sink." + RecordingSink.NAME + ".mode", "sessions+events");
        v.put("sink." + RecordingSink.NAME + ".batch.linger", "20ms");
        b.sinks.keySet().forEach(name -> {
            sinkNames.add(name);
            v.put("sink." + name + ".type", "embedded-" + name);
            v.put("sink." + name + ".batch.linger", "20ms");
        });
        v.put("export.sinks", String.join(", ", sinkNames));
        v.putAll(b.settings);
        v.put("export.sinks", withOwnSink(v.get("export.sinks")));
        return v;
    }

    /**
     * The sink list with the embedded server's own sink first: a {@code setting("export.sinks", ...)} replaces the
     * whole list, and without {@value RecordingSink#NAME} {@code accounting()} and {@code awaitAccounting(...)}
     * would silently see nothing.
     */
    static String withOwnSink(String sinks) {
        List<String> names = new ArrayList<>();
        names.add(RecordingSink.NAME);
        for (String name : sinks == null ? new String[0] : sinks.split(",")) {
            String trimmed = name.trim();
            if (!trimmed.isEmpty() && !trimmed.equals(RecordingSink.NAME)) {
                names.add(trimmed);
            }
        }
        return String.join(", ", names);
    }

    static AuthPlugins plugins(EmbeddedRadiusward.Builder b) {
        List<IdentityStoreProvider> providers = new ArrayList<>();
        Map<String, UserRecord> byName = Map.copyOf(b.users);
        providers.add(IdentityStoreProvider.of("embedded-users", context -> new IdentityStore() {
            @Override
            public Optional<UserRecord> lookup(String userName) {
                return Optional.ofNullable(byName.get(userName.toLowerCase(Locale.ROOT)));
            }

            @Override
            public void close() {}
        }));
        for (int i = 0; i < b.stores.size(); i++) {
            IdentityStore store = b.stores.get(i);
            providers.add(IdentityStoreProvider.of("embedded-store-" + (i + 1), context -> Kept.store(store)));
        }
        List<CredentialVerifierProvider> verifierProviders = new ArrayList<>();
        for (CredentialVerifier verifier : b.verifiers) {
            verifierProviders.add(
                    CredentialVerifierProvider.of("embedded-verifier", context -> Kept.verifier(verifier)));
        }
        return new AuthPlugins(providers, verifierProviders);
    }

    static SinkProvider[] sinkProviders(EmbeddedRadiusward.Builder b) {
        List<SinkProvider> providers = new ArrayList<>();
        providers.add(SinkProvider.of(RecordingSink.TYPE, () -> b.recorder));
        b.sinks.forEach((name, sink) -> providers.add(SinkProvider.of("embedded-" + name, () -> Kept.sink(sink))));
        return providers.toArray(SinkProvider[]::new);
    }

    /** The developer's instances: the server and the exporter close only views of them; we close them once. */
    static List<AutoCloseable> owned(EmbeddedRadiusward.Builder b) {
        List<AutoCloseable> all = new ArrayList<>(b.stores);
        all.addAll(b.verifiers);
        all.addAll(b.sinks.values());
        return all;
    }
}
