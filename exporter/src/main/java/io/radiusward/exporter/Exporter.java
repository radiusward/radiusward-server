/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.radiusward.common.config.ConfigException;
import io.radiusward.export.Attributes;
import io.radiusward.export.SinkContext;
import io.radiusward.export.SinkProvider;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import io.radiusward.radius.dictionary.ParseMode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The exporter of one cluster member: one {@link SinkRunner} thread per configured sink. Sink types come from
 * {@link SinkProvider}s on the class path and in {@code plugins/*.jar}.
 */
public final class Exporter implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(Exporter.class);

    private final List<SinkRunner> runners = new ArrayList<>();
    private final List<Thread> threads = new ArrayList<>();

    private Exporter() {}

    public static Exporter start(List<SinkConfig> sinks, ExporterContext context) {
        Exporter exporter = new Exporter();
        if (sinks.isEmpty()) {
            return exporter;
        }
        Map<String, SinkProvider> providers = providers(context.pluginsDir());
        DictionaryLoader.Builder dictionaries = DictionaryLoader.builder().addBundledFreeRadius(ParseMode.LENIENT);
        if (context.dictionaryDir() != null && Files.isDirectory(context.dictionaryDir())) {
            dictionaries.addDirectory(context.dictionaryDir(), ParseMode.LENIENT);
        }
        Dictionary dictionary = dictionaries.load();
        int index = 0;
        for (SinkConfig sink : sinks) {
            SinkProvider provider = providers.get(sink.type());
            if (provider == null) {
                throw new ConfigException("sink." + sink.name() + ".type: unknown sink type \"" + sink.type()
                        + "\"; available: " + providers.keySet());
            }
            SinkContext sinkContext =
                    new SinkContext(sink.name(), context.memberId(), sink.settings(), new Attributes(dictionary));
            SinkRunner runner = new SinkRunner(sink, provider.create(), sinkContext, context, 7_200_000 + 10 * index++);
            Thread thread = new Thread(runner, "exporter-" + sink.name());
            thread.setDaemon(true);
            exporter.runners.add(runner);
            exporter.threads.add(thread);
            thread.start();
        }
        LOG.info(
                "exporter started: sinks {}",
                sinks.stream().map(SinkConfig::name).toList());
        return exporter;
    }

    static Map<String, SinkProvider> providers(Path pluginsDir) {
        ClassLoader loader = Exporter.class.getClassLoader();
        if (pluginsDir != null && Files.isDirectory(pluginsDir)) {
            try (Stream<Path> jars = Files.list(pluginsDir)) {
                URL[] urls = jars.filter(p -> p.toString().endsWith(".jar"))
                        .sorted()
                        .map(p -> {
                            try {
                                return p.toUri().toURL();
                            } catch (java.net.MalformedURLException e) {
                                throw new IllegalStateException(e);
                            }
                        })
                        .toArray(URL[]::new);
                if (urls.length > 0) {
                    loader = new URLClassLoader(urls, loader);
                    LOG.info("sink plug-ins from {}: {} jar(s)", pluginsDir, urls.length);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        Map<String, SinkProvider> providers = new HashMap<>();
        for (SinkProvider provider : ServiceLoader.load(SinkProvider.class, loader)) {
            providers.putIfAbsent(provider.type(), provider);
        }
        return providers;
    }

    public List<SinkStatus> status() {
        return runners.stream().map(SinkRunner::status).toList();
    }

    @Override
    public void close() {
        runners.forEach(SinkRunner::stop);
        for (Thread t : threads) {
            try {
                t.join(10_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}
