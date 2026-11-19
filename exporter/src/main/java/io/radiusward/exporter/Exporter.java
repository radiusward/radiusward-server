/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.radiusward.common.config.ConfigException;
import io.radiusward.common.management.JsonWriter;
import io.radiusward.common.management.PrometheusWriter;
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
        return start(sinks, List.of(), context);
    }

    /**
     * @param inCode sink providers given in code besides the plug-ins; a type that is also a plug-in's is refused rather
     *     than one silently winning
     */
    public static Exporter start(List<SinkConfig> sinks, List<SinkProvider> inCode, ExporterContext context) {
        Exporter exporter = new Exporter();
        if (sinks.isEmpty()) {
            return exporter;
        }
        Map<String, SinkProvider> providers = providers(context.pluginsDir());
        for (SinkProvider provider : inCode) {
            if (providers.putIfAbsent(provider.type(), provider) != null) {
                throw new ConfigException(
                        "the sink type " + provider.type() + " given in code is also a plug-in's type");
            }
        }
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

    /**
     * The sinks in {@code /state}: lease, positions, lag behind the member's applied log position, rows and errors.
     */
    public void writeState(JsonWriter json, long lastPosition) {
        json.object("export");
        for (SinkStatus sink : status()) {
            json.object(sink.name())
                    .field("type", sink.type())
                    .field("exporting", sink.exporting())
                    .field("leaseOwner", sink.leaseOwner())
                    .field("epoch", sink.epoch())
                    .field("position", sink.position())
                    .field("clusterCheckpoint", sink.clusterCheckpoint())
                    .field("lagBytes", Math.max(0, lastPosition - sink.clusterCheckpoint()))
                    .field("detached", sink.detached())
                    .field("rows", sink.rows())
                    .field("batches", sink.batches())
                    .field("lastBatchMillis", sink.lastBatchNanos() / 1_000_000)
                    .field("lastError", sink.lastError() == null ? "" : sink.lastError())
                    .end();
        }
        json.end();
    }

    /**
     * The sinks in {@code /metrics} (docs/operations/monitoring.md), labelled with the member and the sink.
     *
     * @param lastPosition the member's applied log position, for the lag
     * @param nowMillis wall-clock time, for the age of the newest exported entry
     */
    public void writeMetrics(PrometheusWriter w, String member, long lastPosition, long nowMillis) {
        List<SinkStatus> sinks = status();
        w.gauge("radiusward_export_exporting", "1 on the member that holds the sink's lease");
        sinks.forEach(k -> w.sample(k.exporting() ? 1 : 0, "member", member, "sink", k.name()));
        w.gauge("radiusward_export_lag_bytes", "Accounting log not yet written by the sink");
        sinks.forEach(
                k -> w.sample(Math.max(0, lastPosition - k.clusterCheckpoint()), "member", member, "sink", k.name()));
        w.gauge("radiusward_export_lag_seconds", "Age of the newest exported entry (exporting member only)");
        sinks.stream()
                .filter(SinkStatus::exporting)
                .forEach(k -> w.sample(
                        k.lastEventTime() == 0 || k.clusterCheckpoint() >= lastPosition
                                ? 0
                                : Math.max(0, nowMillis - k.lastEventTime()) / 1000.0,
                        "member",
                        member,
                        "sink",
                        k.name()));
        w.gauge("radiusward_export_detached", "1 when an optional sink has been detached");
        sinks.forEach(k -> w.sample(k.detached() ? 1 : 0, "member", member, "sink", k.name()));
        w.gauge("radiusward_export_epoch", "Lease epoch of the sink");
        sinks.forEach(k -> w.sample(k.epoch(), "member", member, "sink", k.name()));
        w.counter("radiusward_export_rows_total", "Rows written by this member");
        sinks.forEach(k -> w.sample(k.rows(), "member", member, "sink", k.name()));
        w.counter("radiusward_export_batches_total", "Batches written by this member");
        sinks.forEach(k -> w.sample(k.batches(), "member", member, "sink", k.name()));
        w.gauge("radiusward_export_last_batch_seconds", "Duration of the last batch write");
        sinks.forEach(k -> w.sample(k.lastBatchNanos() / 1e9, "member", member, "sink", k.name()));
        w.counter("radiusward_export_errors_total", "Failed sink writes and other sink errors");
        sinks.forEach(k -> w.sample(k.errors(), "member", member, "sink", k.name()));
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
