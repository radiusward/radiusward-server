/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The cluster service applies the replicated log on every member and must reach the same state on each
 * (CONTRIBUTING.md, project rules; ADR 0005): cluster time only, no I/O, no randomness, no wall clock, no
 * hash-ordered {@code java.util} collections. This test fails when production code of the module uses any of them,
 * so the rule does not depend on review alone. Logging is allowed: it never feeds back into the state.
 */
class DeterminismRulesTest {

    private static final Pattern FORBIDDEN = Pattern.compile(String.join(
            "|",
            // wall clock and timers
            "System\\.currentTimeMillis",
            "System\\.nanoTime",
            "Instant\\.now",
            "Clock\\.system",
            "(LocalDate|LocalDateTime|LocalTime|ZonedDateTime|OffsetDateTime)\\.now",
            "Thread\\.sleep",
            // randomness
            "new (java\\.util\\.)?Random\\(",
            "SecureRandom",
            "ThreadLocalRandom",
            "Math\\.random",
            "UUID\\.randomUUID",
            // the environment and I/O
            "System\\.getenv",
            "System\\.getProperty",
            "import java\\.io\\.File",
            "import java\\.nio\\.file\\.",
            "import java\\.net\\.",
            // collections whose iteration order is not the insertion order
            "java\\.util\\.(HashMap|HashSet|Hashtable|IdentityHashMap|WeakHashMap)",
            "import java\\.util\\.concurrent\\.ConcurrentHashMap",
            "\\bnew (HashMap|HashSet|Hashtable|IdentityHashMap|WeakHashMap|ConcurrentHashMap)<"));

    @Test
    void theServiceUsesNoWallClockRandomnessIoOrHashOrderedCollections() throws IOException {
        List<String> violations = new ArrayList<>();
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                List<String> lines = Files.readAllLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i).strip();
                    if (line.startsWith("*") || line.startsWith("//") || line.startsWith("/*")) {
                        continue; // documentation may name what is forbidden
                    }
                    Matcher m = FORBIDDEN.matcher(line);
                    if (m.find()) {
                        violations.add(file.getFileName() + ":" + (i + 1) + " uses " + m.group());
                    }
                }
            }
        }
        assertThat(violations).as("nondeterminism in the cluster service").isEmpty();
    }

    @Test
    void theRulesCatchWhatTheyAreFor() {
        for (String bad : new String[] {
            "long now = System.currentTimeMillis();",
            "Map<Long, Long> m = new HashMap<>();",
            "import java.util.HashSet;",
            "int r = ThreadLocalRandom.current().nextInt();",
            "import java.nio.file.Files;",
            "String home = System.getenv(\"HOME\");"
        }) {
            assertThat(FORBIDDEN.matcher(bad).find()).as(bad).isTrue();
        }
        assertThat(FORBIDDEN
                        .matcher("Long2LongHashMap sqns = new Long2LongHashMap(-1);")
                        .find())
                .as("Agrona's open-addressing maps iterate in an order every member reproduces")
                .isFalse();
    }
}
