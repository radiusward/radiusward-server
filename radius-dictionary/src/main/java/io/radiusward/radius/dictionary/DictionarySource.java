/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/** A dictionary file, either on the classpath or on the filesystem. {@code $INCLUDE} resolves relative to it. */
public sealed interface DictionarySource {

    /** Classpath resource of the bundled FreeRADIUS root dictionary ({@code radius-dictionary-freeradius}). */
    String BUNDLED_FREERADIUS_ROOT = "io/radiusward/radius/dictionary/freeradius/dictionary";

    /** Human readable location used in error messages. */
    String location();

    /** Stable identity used for {@code $INCLUDE} cycle detection. */
    String identity();

    boolean exists();

    InputStream open() throws IOException;

    /** Source of a file named in an {@code $INCLUDE} line of this file. */
    DictionarySource resolve(String include);

    static DictionarySource classpath(String resource) {
        return new Classpath(resource, DictionarySource.class.getClassLoader());
    }

    static DictionarySource classpath(String resource, ClassLoader loader) {
        return new Classpath(resource, loader);
    }

    static DictionarySource file(Path path) {
        return new File(path.toAbsolutePath().normalize());
    }

    /** The FreeRADIUS dictionaries bundled with radiusward. */
    static DictionarySource bundledFreeRadius() {
        return classpath(BUNDLED_FREERADIUS_ROOT);
    }

    record Classpath(String resource, ClassLoader loader) implements DictionarySource {
        @Override
        public String location() {
            return "classpath:" + resource;
        }

        @Override
        public String identity() {
            return location();
        }

        @Override
        public boolean exists() {
            return loader.getResource(resource) != null;
        }

        @Override
        public InputStream open() throws IOException {
            InputStream in = loader.getResourceAsStream(resource);
            if (in == null) {
                throw new IOException("not found: " + location());
            }
            return in;
        }

        @Override
        public DictionarySource resolve(String include) {
            if (include.startsWith("/")) {
                return new Classpath(include.substring(1), loader);
            }
            int slash = resource.lastIndexOf('/');
            String dir = slash >= 0 ? resource.substring(0, slash + 1) : "";
            return new Classpath(Path.of(dir + include).normalize().toString().replace('\\', '/'), loader);
        }
    }

    record File(Path path) implements DictionarySource {
        @Override
        public String location() {
            return path.toString();
        }

        @Override
        public String identity() {
            try {
                return path.toRealPath().toString();
            } catch (IOException e) {
                return path.toString();
            }
        }

        @Override
        public boolean exists() {
            return Files.isRegularFile(path);
        }

        @Override
        public InputStream open() throws IOException {
            return Files.newInputStream(path);
        }

        @Override
        public DictionarySource resolve(String include) {
            Path target = Path.of(include);
            if (!target.isAbsolute()) {
                Path dir = path.getParent();
                target = dir == null ? target : dir.resolve(target);
            }
            return new File(target.normalize());
        }
    }
}
