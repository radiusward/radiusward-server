/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Parses FreeRADIUS-format dictionaries into a {@link Dictionary}.
 *
 * <p>Supports the v3 syntax used by most operator installations ({@code ATTRIBUTE}, {@code VALUE},
 * {@code VENDOR format=}, {@code BEGIN-VENDOR}/{@code END-VENDOR}, {@code BEGIN-TLV},
 * {@code $INCLUDE}, {@code $INCLUDE-}, vendor names in the fifth column) and the v4 subset used by
 * the bundled FreeRADIUS master dictionaries ({@code BEGIN PROTOCOL}, {@code BEGIN <attr>},
 * {@code END-VENDOR <name>}, {@code ALIAS}, {@code MEMBER}, {@code DEFINE}, {@code FLAGS},
 * dotted and relative attribute numbers).
 *
 * <p>Sources are loaded in the order they were added; later definitions extend or override earlier
 * ones. See {@code docs/dictionaries.md}.
 */
public final class DictionaryLoader {

    private final List<Entry> entries;

    private DictionaryLoader(List<Entry> entries) {
        this.entries = List.copyOf(entries);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Loads only the bundled FreeRADIUS dictionaries in strict mode. */
    public static Dictionary loadBundled() {
        return builder()
                .add(DictionarySource.bundledFreeRadius(), ParseMode.STRICT)
                .load();
    }

    /** Builder collecting dictionary sources in load order. */
    public static final class Builder {
        private final List<Entry> entries = new ArrayList<>();
        private ParseMode defaultMode = ParseMode.LENIENT;

        private Builder() {}

        /** Mode used by {@link #add(DictionarySource)} and {@link #addDirectory(Path)}. Defaults to lenient. */
        public Builder mode(ParseMode mode) {
            this.defaultMode = mode;
            return this;
        }

        public Builder add(DictionarySource source) {
            return add(source, defaultMode);
        }

        public Builder add(DictionarySource source, ParseMode mode) {
            entries.add(new Entry(source, mode, false));
            return this;
        }

        /** Adds the bundled FreeRADIUS dictionaries. */
        public Builder addBundledFreeRadius(ParseMode mode) {
            return add(DictionarySource.bundledFreeRadius(), mode);
        }

        /**
         * Adds every regular, non-hidden file in {@code directory} in name order, e.g.
         * {@code /etc/radiusward/dictionary.d/}. A missing directory is ignored with a warning.
         */
        public Builder addDirectory(Path directory) {
            return addDirectory(directory, defaultMode);
        }

        public Builder addDirectory(Path directory, ParseMode mode) {
            if (!Files.isDirectory(directory)) {
                entries.add(new Entry(DictionarySource.file(directory), mode, true));
                return this;
            }
            try (Stream<Path> files = Files.list(directory)) {
                files.filter(Files::isRegularFile)
                        .filter(p -> !p.getFileName().toString().startsWith("."))
                        .sorted()
                        .forEach(p -> entries.add(new Entry(DictionarySource.file(p), mode, false)));
            } catch (IOException e) {
                throw new DictionaryException("cannot list dictionary directory " + directory, e);
            }
            return this;
        }

        public Dictionary load() {
            return new DictionaryLoader(entries).load();
        }
    }

    private record Entry(DictionarySource source, ParseMode mode, boolean missingDirectory) {}

    private Dictionary load() {
        DictionaryParser parser = new DictionaryParser();
        for (Entry entry : entries) {
            if (entry.missingDirectory()) {
                parser.warnings.add("dictionary directory not found, skipped: "
                        + entry.source().location());
                continue;
            }
            parser.parseTopLevel(entry.source(), entry.mode());
        }
        return parser.finish();
    }
}
