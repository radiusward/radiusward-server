/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.file;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.export.Attributes;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.FencedException;
import io.radiusward.export.SessionSnapshot;
import io.radiusward.export.SinkContext;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileSinkTest {

    private static final Attributes ATTRIBUTES = new Attributes(DictionaryLoader.loadBundled());

    @TempDir
    Path dir;

    private SinkContext context(String mode) {
        return new SinkContext("archive", 2, Map.of("dir", dir.toString(), "mode", mode), ATTRIBUTES);
    }

    private static Batch batch(long epoch, long from, long to, int n) {
        ExportEvent event = new ExportEvent(
                new UUID(n, n),
                to,
                1_780_000_000_000L,
                7,
                1,
                new UUID(1, 1),
                "s1",
                3,
                ExportEvent.EventOutcome.APPLIED,
                60L,
                null,
                10,
                20,
                new byte[] {1, 7, 'a', 'l', 'i', 'c', 'e'});
        SessionSnapshot session = new SessionSnapshot(
                new UUID(1, 1),
                to,
                7,
                "s1",
                SessionSnapshot.State.ACTIVE,
                SessionSnapshot.CloseCause.NONE,
                3,
                60L,
                10,
                20,
                1_780_000_000_000L,
                null,
                null,
                new byte[] {1, 7, 'a', 'l', 'i', 'c', 'e'});
        return new Batch("archive", epoch, from, to, 1_780_000_000_000L, List.of(event), List.of(session));
    }

    private List<String> lines() throws Exception {
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.toString().endsWith(".jsonl"))
                    .sorted()
                    .flatMap(p -> {
                        try {
                            return Files.readAllLines(p).stream();
                        } catch (java.io.IOException e) {
                            throw new java.io.UncheckedIOException(e);
                        }
                    })
                    .toList();
        }
    }

    @Test
    void writesJsonLinesAndResumesFromTheStoredPosition() throws Exception {
        FileSink sink = new FileSink();
        sink.open(context("sessions+events"));
        assertThat(sink.storedPosition()).isEqualTo(-1);
        sink.write(batch(1, 0, 100, 1));
        sink.write(batch(1, 100, 200, 2));
        sink.close();

        assertThat(lines()).hasSize(4);
        assertThat(lines().get(0))
                .startsWith("{\"type\":\"event\",\"event_id\":\"00000000-0000-0001-0000-000000000001\"")
                .contains("\"user_name\":\"alice\"")
                .contains("\"outcome\":\"applied\"")
                .contains("\"attributes\":null");
        assertThat(lines().get(1)).startsWith("{\"type\":\"session\"").contains("\"version\":100");

        FileSink again = new FileSink();
        again.open(context("sessions+events"));
        assertThat(again.storedPosition()).isEqualTo(200);
        again.close();
    }

    @Test
    void anUnconfirmedTailIsCutOffOnOpen() throws Exception {
        FileSink sink = new FileSink();
        sink.open(context("sessions"));
        sink.write(batch(1, 0, 100, 1));
        sink.close();
        Path file;
        try (Stream<Path> files = Files.list(dir)) {
            file = files.filter(p -> p.toString().endsWith(".jsonl"))
                    .findFirst()
                    .orElseThrow();
        }
        Files.writeString(file, "{\"type\":\"session\",\"half", java.nio.file.StandardOpenOption.APPEND);

        FileSink again = new FileSink();
        again.open(context("sessions"));
        again.write(batch(1, 100, 200, 2));
        again.close();
        assertThat(lines()).hasSize(2).allSatisfy(l -> assertThat(l).endsWith("}"));
        assertThat(lines()).noneMatch(l -> l.contains("half"));
    }

    @Test
    void olderEpochIsFenced() throws Exception {
        FileSink sink = new FileSink();
        sink.open(context("sessions"));
        sink.write(batch(5, 0, 100, 1));
        assertThatThrownBy(() -> sink.write(batch(4, 100, 200, 2))).isInstanceOf(FencedException.class);
        sink.close();
    }
}
