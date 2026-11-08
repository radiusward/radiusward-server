/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.distribution;

import io.radiusward.cluster.node.ClusterNodeMain;
import io.radiusward.gateway.GatewayMain;
import java.util.Arrays;

/** {@code java -jar radiusward.jar cluster-node|gateway --config <file>...}. */
public final class Main {

    private Main() {}

    public static void main(String[] args) {
        if (args.length == 0) {
            usage();
            System.exit(64);
        }
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        try {
            switch (args[0]) {
                case "cluster-node" -> ClusterNodeMain.main(rest);
                case "gateway" -> GatewayMain.main(rest);
                case "cluster-tool" -> io.aeron.cluster.ClusterTool.main(rest); // e.g. <cluster-dir> snapshot
                case "radclient" -> io.radiusward.tools.radclient.RadClient.main(rest);
                case "admin" -> io.radiusward.tools.admin.AdminMain.main(rest);
                case "probe" -> System.exit(Probe.run(rest));
                case "version", "--version" -> System.out.println(version());
                default -> {
                    usage();
                    System.exit(64);
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println("radiusward: " + e.getMessage());
            System.exit(64);
        }
    }

    static String version() {
        String v = Main.class.getPackage().getImplementationVersion();
        return "radiusward " + (v == null ? "dev" : v);
    }

    private static void usage() {
        System.err.println("""
                usage: radiusward cluster-node --config <file.properties> [--config ...]
                       radiusward gateway      --config <file.properties> [--config ...]
                       radiusward cluster-tool <cluster-dir> <command>   (Aeron ClusterTool: describe, snapshot, ...)
                       radiusward radclient ...                          (test client: acct, replay, decode, load)
                       radiusward admin state|verify-acks ...            (query the replicated state)
                       radiusward probe <url>                            (exit 0 if the URL answers 200; health checks)
                       radiusward version""");
    }
}
