/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code radiusward admin state|verify-acks}: queries the replicated state through the cluster log.
 *
 * <pre>
 * admin state       --members h0,h1,h2 [--base-port 9000] [--egress-host localhost]
 * admin verify-acks --members ... --ack-log acks.csv --nas-id 1001
 * </pre>
 */
public final class AdminMain {

    static final int EXIT_OK = 0;
    static final int EXIT_FAILED = 1;
    static final int EXIT_USAGE = 64;

    private AdminMain() {}

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 0) {
            err.println(usage());
            return EXIT_USAGE;
        }
        Map<String, String> options;
        try {
            options = parse(Arrays.copyOfRange(args, 1, args.length));
            if (!options.containsKey("members")) {
                throw new IllegalArgumentException("--members is required");
            }
        } catch (IllegalArgumentException e) {
            err.println("admin: " + e.getMessage());
            err.println(usage());
            return EXIT_USAGE;
        }
        if (!args[0].equals("state") && !args[0].equals("verify-acks")) {
            err.println("admin: unknown command " + args[0]);
            err.println(usage());
            return EXIT_USAGE;
        }
        if (args[0].equals("verify-acks") && (!options.containsKey("ack-log") || !options.containsKey("nas-id"))) {
            err.println("admin: verify-acks needs --ack-log and --nas-id");
            return EXIT_USAGE;
        }
        try (AdminClient admin = new AdminClient(
                List.of(options.get("members").split(",")),
                Integer.parseInt(options.getOrDefault("base-port", "9000")),
                options.getOrDefault("egress-host", "localhost"))) {
            AdminClient.State state = admin.state();
            out.println("applied=" + state.applied());
            out.println("duplicates=" + state.duplicates());
            out.println("stale=" + state.stale());
            out.println("rejected=" + state.rejected());
            out.println("active=" + state.active());
            out.println("stopped=" + state.stopped());
            out.println("digest=" + Long.toHexString(state.digest()));
            if (args[0].equals("state")) {
                return EXIT_OK;
            }
            AckVerifier.Report report = AckVerifier.verify(
                    Path.of(options.get("ack-log")), Integer.parseInt(options.get("nas-id")), admin::session);
            report.lost().stream().limit(20).forEach(line -> out.println("lost " + line));
            out.println("sessions=" + report.sessions());
            out.println("lost=" + report.lost().size());
            return report.ok() ? EXIT_OK : EXIT_FAILED;
        } catch (IOException | RuntimeException e) {
            err.println("admin: " + e.getMessage());
            return EXIT_FAILED;
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
                usage: admin state       --members h0,h1,h2 [--base-port 9000] [--egress-host <reachable own address>]
                       admin verify-acks --members ... --ack-log <acks.csv> --nas-id <id>
                exit: 0 ok, 1 acknowledged events missing or no answer, 64 usage""";
    }
}
