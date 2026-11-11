/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.management;

import java.util.HashSet;
import java.util.Set;

/**
 * Writes the Prometheus text exposition format (version 0.0.4) without a client library: {@code # HELP} and
 * {@code # TYPE} once per family, then its samples. Names follow Prometheus conventions: {@code radiusward_}
 * prefix, base units in the name ({@code _bytes}, {@code _seconds}), {@code _total} for counters.
 */
public final class PrometheusWriter {

    public static final String CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

    private final StringBuilder out = new StringBuilder(4096);
    private final Set<String> families = new HashSet<>();
    private String family;

    /** Starts (or continues) a family; HELP and TYPE are written the first time only. */
    public PrometheusWriter family(String name, String type, String help) {
        if (!name.matches("[a-zA-Z_:][a-zA-Z0-9_:]*")) {
            throw new IllegalArgumentException("invalid metric name " + name);
        }
        family = name;
        if (families.add(name)) {
            out.append("# HELP ")
                    .append(name)
                    .append(' ')
                    .append(help.replace("\\", "\\\\").replace("\n", "\\n"))
                    .append('\n');
            out.append("# TYPE ").append(name).append(' ').append(type).append('\n');
        }
        return this;
    }

    public PrometheusWriter counter(String name, String help) {
        return family(name, "counter", help);
    }

    public PrometheusWriter gauge(String name, String help) {
        return family(name, "gauge", help);
    }

    /** A sample of the current family; {@code labels} are name/value pairs. */
    public PrometheusWriter sample(double value, String... labels) {
        if (family == null) {
            throw new IllegalStateException("sample before family");
        }
        if (labels.length % 2 != 0) {
            throw new IllegalArgumentException("labels must be name/value pairs");
        }
        out.append(family);
        if (labels.length > 0) {
            out.append('{');
            for (int i = 0; i < labels.length; i += 2) {
                if (i > 0) {
                    out.append(',');
                }
                out.append(labels[i]).append("=\"");
                String v = labels[i + 1] == null ? "" : labels[i + 1];
                for (int c = 0; c < v.length(); c++) {
                    char ch = v.charAt(c);
                    switch (ch) {
                        case '\\' -> out.append("\\\\");
                        case '"' -> out.append("\\\"");
                        case '\n' -> out.append("\\n");
                        default -> out.append(ch);
                    }
                }
                out.append('"');
            }
            out.append('}');
        }
        out.append(' ');
        if (value == Math.rint(value) && Math.abs(value) < 1e15) {
            out.append((long) value);
        } else if (Double.isNaN(value)) {
            out.append("NaN");
        } else if (Double.isInfinite(value)) {
            out.append(value > 0 ? "+Inf" : "-Inf");
        } else {
            out.append(value);
        }
        out.append('\n');
        return this;
    }

    /**
     * A histogram of the current family (started with {@code family(name, "histogram", help)}): {@code _bucket} lines
     * for each upper bound and {@code +Inf}, then {@code _sum} and {@code _count}.
     *
     * @param bounds upper bounds in ascending order
     * @param cumulative observations at or below each bound, {@code bounds.length + 1} values (the last is +Inf)
     */
    public PrometheusWriter histogram(double[] bounds, long[] cumulative, double sum, String... labels) {
        if (cumulative.length != bounds.length + 1) {
            throw new IllegalArgumentException("one count per bound and one for +Inf");
        }
        String base = family;
        String[] withLe = java.util.Arrays.copyOf(labels, labels.length + 2);
        withLe[labels.length] = "le";
        for (int i = 0; i <= bounds.length; i++) {
            withLe[labels.length + 1] = i < bounds.length ? Double.toString(bounds[i]) : "+Inf";
            family = base + "_bucket";
            sample(cumulative[i], withLe);
        }
        family = base + "_sum";
        sample(sum, labels);
        family = base + "_count";
        sample(cumulative[bounds.length], labels);
        family = base;
        return this;
    }

    public String finish() {
        return out.toString();
    }

    private static final java.util.regex.Pattern LINE =
            java.util.regex.Pattern.compile("# (HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]* .+"
                    + "|[a-zA-Z_:][a-zA-Z0-9_:]*(\\{([a-zA-Z_][a-zA-Z0-9_]*=\"([^\"\\\\]|\\\\.)*\",?)*\\})?"
                    + " (-?[0-9.eE+-]+|NaN|[+-]Inf)");

    /**
     * Checks exposition text: every line valid, {@code # TYPE} once per family and before its samples.
     *
     * @throws IllegalArgumentException with the offending line
     */
    public static void validate(String text) {
        Set<String> typed = new HashSet<>();
        Set<String> histograms = new HashSet<>();
        for (String line : text.split("\n")) {
            if (!LINE.matcher(line).matches()) {
                throw new IllegalArgumentException("invalid metrics line: " + line);
            }
            if (line.startsWith("# TYPE ")) {
                if (!typed.add(line.split(" ")[2])) {
                    throw new IllegalArgumentException("TYPE twice: " + line);
                }
                if (line.endsWith(" histogram")) {
                    histograms.add(line.split(" ")[2]);
                }
            } else if (!line.startsWith("#")
                    && !typed.contains(sampleFamily(line.replaceAll("[{ ].*", ""), histograms))) {
                throw new IllegalArgumentException("sample before its TYPE: " + line);
            }
        }
    }

    /** The family a sample belongs to: a histogram's {@code _bucket}, {@code _sum} and {@code _count} name it. */
    private static String sampleFamily(String name, Set<String> histograms) {
        for (String suffix : new String[] {"_bucket", "_sum", "_count"}) {
            if (name.endsWith(suffix)) {
                String base = name.substring(0, name.length() - suffix.length());
                if (histograms.contains(base)) {
                    return base;
                }
            }
        }
        return name;
    }
}
