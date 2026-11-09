/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import io.radiusward.export.SqlMigrations;
import io.radiusward.sink.postgres.PostgresSink;
import java.io.PrintStream;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code radiusward admin}: the replicated state, sinks and export checks.
 *
 * <pre>
 * admin state          --members h0,h1,h2 [--base-port 9000] [--egress-host localhost]
 * admin verify-acks    --members ... --ack-log acks.csv --nas-id 1001
 * admin sinks          --members ...
 * admin resync         --members ... --sink pg --position 0
 * admin activate-version --members ... --version 6
 * admin export-schema  [--type postgres]
 * admin verify-export  --jdbc-url ... [--jdbc-user u --jdbc-password p] --ack-log acks.csv --nas-id 1001 [--members ...]
 * </pre>
 *
 * <p>{@code verify-acks} and {@code verify-export} take {@code --identity nas-identifier} when the NAS entry tells
 * apart the devices behind it by NAS-Identifier (ADR 0019), like the load generator's simulated NAS.
 */
public final class AdminMain {

    static final int EXIT_OK = 0;
    static final int EXIT_FAILED = 1;
    static final int EXIT_USAGE = 64;

    private AdminMain() {}

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Runs one command; returns the exit code. Public for embedding and tests. */
    public static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 0) {
            err.println(usage());
            return EXIT_USAGE;
        }
        String command = args[0];
        Map<String, String> o;
        try {
            o = parse(Arrays.copyOfRange(args, 1, args.length));
            switch (command) {
                case "state", "sinks" -> need(o, "members");
                case "verify-acks" -> need(o, "members", "ack-log", "nas-id");
                case "resync" -> need(o, "members", "sink", "position");
                case "activate-version" -> need(o, "members", "version");
                case "verify-export" -> need(o, "jdbc-url", "ack-log", "nas-id");
                case "export-schema" -> {}
                default -> throw new IllegalArgumentException("unknown command " + command);
            }
            byDevice(o);
        } catch (IllegalArgumentException e) {
            err.println("admin: " + e.getMessage());
            err.println(usage());
            return EXIT_USAGE;
        }
        try {
            return switch (command) {
                case "export-schema" -> exportSchema(o, out, err);
                case "verify-export" -> verifyExport(o, out);
                default -> withCluster(command, o, out);
            };
        } catch (Exception e) {
            err.println("admin: " + e.getMessage());
            return EXIT_FAILED;
        }
    }

    private static AdminClient cluster(Map<String, String> o) {
        return new AdminClient(
                List.of(o.get("members").split(",")),
                Integer.parseInt(o.getOrDefault("base-port", "9000")),
                o.getOrDefault("egress-host", "localhost"));
    }

    private static int withCluster(String command, Map<String, String> o, PrintStream out) throws Exception {
        try (AdminClient admin = cluster(o)) {
            switch (command) {
                case "sinks" -> {
                    printSinks(admin.sinks(), out);
                    return EXIT_OK;
                }
                case "resync" -> {
                    AdminClient.Sinks sinks = admin.resync(o.get("sink"), Long.parseLong(o.get("position")));
                    if (sinks.sinks().stream().noneMatch(s -> s.name().equals(o.get("sink")))) {
                        out.println("unknown sink " + o.get("sink"));
                        return EXIT_FAILED;
                    }
                    out.println(
                            "resync of " + o.get("sink") + " from log position " + o.get("position") + " requested");
                    printSinks(sinks, out);
                    return EXIT_OK;
                }
                case "activate-version" -> {
                    AdminClient.Activation a = admin.activateVersion(Integer.parseInt(o.get("version")));
                    out.println("result=" + a.result());
                    out.println("activeVersion=" + a.activeVersion());
                    out.println("lowestSupportedVersion=" + a.lowestSupportedVersion());
                    return a.result() == io.radiusward.protocol.ActivationResult.ACTIVATED ? EXIT_OK : EXIT_FAILED;
                }
                default -> {}
            }
            AdminClient.State state = admin.state();
            out.println("applied=" + state.applied());
            out.println("duplicates=" + state.duplicates());
            out.println("stale=" + state.stale());
            out.println("rejected=" + state.rejected());
            out.println("active=" + state.active());
            out.println("stopped=" + state.stopped());
            out.println("digest=" + Long.toHexString(state.digest()));
            out.println("stateVersion=" + state.activeVersion());
            out.println("lowestSupportedVersion=" + state.lowestSupportedVersion());
            if (command.equals("state")) {
                return EXIT_OK;
            }
            AckVerifier.Report report = AckVerifier.verify(
                    Path.of(o.get("ack-log")), Integer.parseInt(o.get("nas-id")), byDevice(o), admin::session);
            return report(report, out);
        }
    }

    private static void printSinks(AdminClient.Sinks sinks, PrintStream out) {
        out.printf(
                "%-16s %14s %14s %6s %6s %8s %8s %6s%n",
                "sink", "checkpoint", "lag_bytes", "owner", "epoch", "required", "detached", "resync");
        for (AdminClient.SinkInfo s : sinks.sinks()) {
            out.printf(
                    "%-16s %14d %14d %6d %6d %8s %8s %6s%n",
                    s.name(),
                    s.checkpoint(),
                    Math.max(0, sinks.logPosition() - s.checkpoint()),
                    s.owner(),
                    s.epoch(),
                    s.required(),
                    s.detached(),
                    s.resyncPending());
        }
    }

    private static int exportSchema(Map<String, String> o, PrintStream out, PrintStream err) {
        String type = o.getOrDefault("type", "postgres");
        if (!type.equals("postgres")) {
            err.println("admin: export-schema knows the built-in sink types: postgres");
            return EXIT_USAGE;
        }
        out.print(SqlMigrations.script(PostgresSink.migrations()));
        return EXIT_OK;
    }

    private static int verifyExport(Map<String, String> o, PrintStream out) throws Exception {
        try (Connection db = DriverManager.getConnection(
                o.get("jdbc-url"), o.getOrDefault("jdbc-user", null), o.getOrDefault("jdbc-password", null))) {
            AckVerifier.Report report;
            if (o.containsKey("members")) {
                try (AdminClient admin = cluster(o)) {
                    report = ExportVerifier.verify(
                            Path.of(o.get("ack-log")),
                            Integer.parseInt(o.get("nas-id")),
                            byDevice(o),
                            db,
                            admin::session);
                }
            } else {
                report = ExportVerifier.verify(
                        Path.of(o.get("ack-log")), Integer.parseInt(o.get("nas-id")), byDevice(o), db, null);
            }
            return report(report, out);
        }
    }

    private static int report(AckVerifier.Report report, PrintStream out) {
        report.lost().stream().limit(20).forEach(line -> out.println("lost " + line));
        out.println("sessions=" + report.sessions());
        out.println("lost=" + report.lost().size());
        return report.ok() ? EXIT_OK : EXIT_FAILED;
    }

    /** {@code --identity}: {@code source-ip} (default) or {@code nas-identifier}. */
    private static boolean byDevice(Map<String, String> o) {
        String identity = o.getOrDefault("identity", "source-ip");
        return switch (identity) {
            case "source-ip" -> false;
            case "nas-identifier" -> true;
            default -> throw new IllegalArgumentException("--identity: expected source-ip or nas-identifier");
        };
    }

    private static void need(Map<String, String> o, String... keys) {
        for (String k : keys) {
            if (!o.containsKey(k)) {
                throw new IllegalArgumentException("--" + k + " is required");
            }
        }
    }

    static Map<String, String> parse(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--") || i + 1 == args.length) {
                throw new IllegalArgumentException("expected --option value, got " + args[i]);
            }
            options.put(args[i].substring(2), args[++i]);
        }
        return options;
    }

    static String usage() {
        return """
                usage: admin state          --members h0,h1,h2 [--base-port 9000] [--egress-host <reachable own address>]
                       admin verify-acks    --members ... --ack-log <acks.csv> --nas-id <id>
                       admin sinks          --members ...
                       admin resync         --members ... --sink <name> --position <log position>
                       admin activate-version --members ... --version <n>   (after every member runs a release with n)
                       admin export-schema  [--type postgres]          (full SQL for DBAs, schema.manage=none)
                       admin verify-export  --jdbc-url <url> [--jdbc-user u --jdbc-password p] --ack-log <acks.csv>
                                            --nas-id <id> [--members ...]   (sessions in the database vs. acks/cluster)
                       verify-acks/verify-export: [--identity nas-identifier] when the NAS entry identifies devices
                exit: 0 ok, 1 something missing or no answer, 64 usage""";
    }
}
