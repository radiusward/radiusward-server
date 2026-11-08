/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.config;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Configuration from Java properties files with environment variable overrides (ADR 0010).
 *
 * <ul>
 *   <li>Files load in order; later files override earlier ones.
 *   <li>Every key can be overridden by an environment variable: {@code cluster.node.id} →
 *       {@code RADIUSWARD_CLUSTER_NODE_ID} (upper case, every non-alphanumeric character becomes {@code _}).
 *   <li>Values may reference environment variables: {@code ${env:NAS_SECRET}} or
 *       {@code ${env:NAS_SECRET:-default}} — used for secrets.
 *   <li>Typed accessors fail with a {@link ConfigException} naming the key.
 * </ul>
 *
 * Immutable and thread-safe. Read at startup, never on the hot path.
 */
public final class Config {

    public static final String ENV_PREFIX = "RADIUSWARD_";

    private static final Pattern ENV_REFERENCE = Pattern.compile("\\$\\{env:([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?}");

    private final Map<String, String> values;
    private final Map<String, String> env;

    private Config(Map<String, String> values, Map<String, String> env) {
        this.values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        this.env = env;
    }

    /** Loads the files in order, using the process environment for overrides. */
    public static Config load(Path... files) {
        return load(List.of(files), System.getenv());
    }

    public static Config load(List<Path> files, Map<String, String> env) {
        Map<String, String> values = new LinkedHashMap<>();
        for (Path file : files) {
            Properties properties = new Properties();
            try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                properties.load(reader);
            } catch (IOException e) {
                throw new ConfigException("cannot read configuration file " + file, e);
            }
            for (String key : new TreeSet<>(properties.stringPropertyNames())) {
                values.put(key, properties.getProperty(key).trim());
            }
        }
        return new Config(values, env);
    }

    /** Configuration from a map, with the given environment (tests, embedded use). */
    public static Config of(Map<String, String> values, Map<String, String> env) {
        return new Config(values, env);
    }

    public static Config of(Map<String, String> values) {
        return new Config(values, Map.of());
    }

    /** A copy with extra values that take precedence over the files (not over the environment). */
    public Config with(Map<String, String> overrides) {
        Map<String, String> merged = new LinkedHashMap<>(values);
        merged.putAll(overrides);
        return new Config(merged, env);
    }

    /** Environment variable that overrides {@code key}. */
    public static String envName(String key) {
        return ENV_PREFIX + key.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_");
    }

    // ---- raw access ----------------------------------------------------------------------------

    /** The resolved value, or {@code null} if the key is not set anywhere. */
    public String raw(String key) {
        String fromEnv = env.get(envName(key));
        String value = fromEnv != null ? fromEnv : values.get(key);
        return value == null ? null : resolve(key, value);
    }

    public boolean has(String key) {
        return raw(key) != null;
    }

    /**
     * Distinct next segments of keys below {@code prefix} from the files, e.g. {@code names("nas")} for
     * {@code nas.core.address}, {@code nas.edge.secret} → {@code [core, edge]}. Sorted.
     */
    public Set<String> names(String prefix) {
        String p = prefix.endsWith(".") ? prefix : prefix + ".";
        Set<String> names = new TreeSet<>();
        for (String key : values.keySet()) {
            if (key.startsWith(p) && key.length() > p.length()) {
                String rest = key.substring(p.length());
                int dot = rest.indexOf('.');
                names.add(dot < 0 ? rest : rest.substring(0, dot));
            }
        }
        return names;
    }

    // ---- typed access --------------------------------------------------------------------------

    public String string(String key) {
        String value = raw(key);
        if (value == null || value.isEmpty()) {
            throw missing(key);
        }
        return value;
    }

    public String string(String key, String fallback) {
        String value = raw(key);
        return value == null || value.isEmpty() ? fallback : value;
    }

    public int integer(String key) {
        return parseInt(key, string(key));
    }

    public int integer(String key, int fallback) {
        return has(key) ? integer(key) : fallback;
    }

    public long longValue(String key) {
        String value = string(key);
        try {
            return Long.parseLong(value.replace("_", ""));
        } catch (NumberFormatException e) {
            throw invalid(key, value, "an integer");
        }
    }

    public long longValue(String key, long fallback) {
        return has(key) ? longValue(key) : fallback;
    }

    public boolean bool(String key, boolean fallback) {
        if (!has(key)) {
            return fallback;
        }
        String value = string(key).toLowerCase(Locale.ROOT);
        return switch (value) {
            case "true", "yes", "on", "1" -> true;
            case "false", "no", "off", "0" -> false;
            default -> throw invalid(key, value, "true or false");
        };
    }

    /** Durations: {@code 250ms}, {@code 10s}, {@code 5m}, {@code 2h}, {@code 1d}; a bare number means milliseconds. */
    public Duration duration(String key) {
        String value = string(key);
        Matcher m = Pattern.compile("(\\d+)\\s*(ms|s|m|h|d)?").matcher(value.toLowerCase(Locale.ROOT));
        if (!m.matches()) {
            throw invalid(key, value, "a duration such as 500ms, 10s, 5m, 2h");
        }
        long n = Long.parseLong(m.group(1));
        String unit = m.group(2) == null ? "ms" : m.group(2);
        return switch (unit) {
            case "ms" -> Duration.ofMillis(n);
            case "s" -> Duration.ofSeconds(n);
            case "m" -> Duration.ofMinutes(n);
            case "h" -> Duration.ofHours(n);
            default -> Duration.ofDays(n);
        };
    }

    public Duration duration(String key, Duration fallback) {
        return has(key) ? duration(key) : fallback;
    }

    /** Sizes in bytes: {@code 512}, {@code 64k}, {@code 4m}, {@code 1g}. */
    public long bytes(String key) {
        String value = string(key);
        Matcher m = Pattern.compile("(\\d+)\\s*([kmg])?b?").matcher(value.toLowerCase(Locale.ROOT));
        if (!m.matches()) {
            throw invalid(key, value, "a size such as 512, 64k, 4m, 1g");
        }
        long n = Long.parseLong(m.group(1));
        String unit = m.group(2);
        if (unit == null) {
            return n;
        }
        return switch (unit) {
            case "k" -> n << 10;
            case "m" -> n << 20;
            default -> n << 30;
        };
    }

    public long bytes(String key, long fallback) {
        return has(key) ? bytes(key) : fallback;
    }

    /** Comma separated list, entries trimmed, empty entries dropped. */
    public List<String> list(String key) {
        return Arrays.stream(string(key).split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    public List<String> list(String key, List<String> fallback) {
        return has(key) ? list(key) : fallback;
    }

    public <E extends Enum<E>> E enumValue(String key, Class<E> type, E fallback) {
        if (!has(key)) {
            return fallback;
        }
        String value = string(key);
        try {
            return Enum.valueOf(type, value.toUpperCase(Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException e) {
            throw invalid(
                    key,
                    value,
                    "one of " + Arrays.toString(type.getEnumConstants()).toLowerCase(Locale.ROOT));
        }
    }

    // ---- helpers -------------------------------------------------------------------------------

    private String resolve(String key, String value) {
        Matcher m = ENV_REFERENCE.matcher(value);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String replacement = env.get(m.group(1));
            if (replacement == null) {
                replacement = m.group(2);
            }
            if (replacement == null) {
                throw new ConfigException(key + ": environment variable " + m.group(1) + " is not set");
            }
            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(out);
        return out.toString();
    }

    private int parseInt(String key, String value) {
        try {
            return Integer.parseInt(value.replace("_", ""));
        } catch (NumberFormatException e) {
            throw invalid(key, value, "an integer");
        }
    }

    private static ConfigException missing(String key) {
        return new ConfigException(key + ": required (set it in the properties file or " + envName(key) + ")");
    }

    private static ConfigException invalid(String key, String value, String expected) {
        return new ConfigException(key + ": expected " + expected + ", got \"" + value + "\"");
    }
}
