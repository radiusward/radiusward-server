/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.config;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Parses {@code --config <file> [--config <file>]...} command lines. */
public final class ConfigArgs {

    private ConfigArgs() {}

    /** The files in order; throws {@link IllegalArgumentException} with {@code usage} on anything else. */
    public static List<Path> files(String[] args, String usage) {
        List<Path> files = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--config".equals(args[i]) && i + 1 < args.length) {
                files.add(Path.of(args[++i]));
            } else {
                throw new IllegalArgumentException("usage: " + usage);
            }
        }
        if (files.isEmpty()) {
            throw new IllegalArgumentException("usage: " + usage);
        }
        return files;
    }
}
