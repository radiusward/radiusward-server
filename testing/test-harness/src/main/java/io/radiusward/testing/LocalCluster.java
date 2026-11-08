/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.cluster.node.ClusterNodeConfig;
import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.common.Profile;
import io.radiusward.gateway.Gateway;
import io.radiusward.gateway.GatewayConfig;
import io.radiusward.gateway.NasClient;
import io.radiusward.gateway.NasRegistry;
import io.radiusward.tools.admin.AdminClient;
import java.io.File;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import org.agrona.CloseHelper;

/**
 * A complete radiusward cluster in one JVM: cluster members and gateways on loopback with their own
 * directories and free ports. Used by integration tests and {@link DevCluster}. Real Aeron, real UDP, real
 * fsync; only {@code kill -9} cannot be simulated here (see the e2e tests).
 */
public final class LocalCluster implements AutoCloseable {

    public static final String SECRET = "testing123";
    public static final String NAS_NAME = "local";
    public static final int NAS_ID = 1001;

    private final File baseDir;
    private final int basePort;
    private final int memberCount;
    private final ClusterNode[] nodes;
    private final List<Gateway> gateways = new ArrayList<>();
    private final Duration snapshotInterval;

    private LocalCluster(File baseDir, int basePort, int memberCount, Duration snapshotInterval) {
        this.baseDir = baseDir;
        this.basePort = basePort;
        this.memberCount = memberCount;
        this.nodes = new ClusterNode[memberCount];
        this.snapshotInterval = snapshotInterval;
    }

    /** Starts {@code members} cluster nodes and {@code gatewayCount} gateways (RADIUS ports chosen freely). */
    public static LocalCluster start(File baseDir, int members, int gatewayCount) {
        return start(baseDir, members, gatewayCount, freePortBase(members), new int[gatewayCount], Duration.ZERO);
    }

    public static LocalCluster start(
            File baseDir, int members, int gatewayCount, int basePort, int[] radiusPorts, Duration snapshotInterval) {
        LocalCluster cluster = new LocalCluster(baseDir, basePort, members, snapshotInterval);
        try {
            for (int i = 0; i < members; i++) {
                cluster.startNode(i);
            }
            for (int g = 0; g < gatewayCount; g++) {
                cluster.startGateway(g + 1, radiusPorts[g]);
            }
            return cluster;
        } catch (RuntimeException e) {
            cluster.close();
            throw e;
        }
    }

    public List<String> members() {
        List<String> members = new ArrayList<>();
        for (int i = 0; i < memberCount; i++) {
            members.add("localhost");
        }
        return members;
    }

    public int basePort() {
        return basePort;
    }

    public ClusterNodeConfig nodeConfig(int id) {
        return new ClusterNodeConfig(
                id,
                members(),
                basePort,
                new File(baseDir, "data/node-" + id),
                new File(baseDir, "aeron/node-" + id).getPath(),
                Profile.SMALL,
                Duration.ofMillis(1500),
                Duration.ofMillis(500),
                Duration.ofSeconds(10),
                snapshotInterval,
                2,
                0,
                AccountingStateMachine.Settings.defaults(Profile.SMALL.maxSessions()),
                Duration.ofSeconds(60));
    }

    public void startNode(int id) {
        if (nodes[id] != null) {
            throw new IllegalStateException("node " + id + " already running");
        }
        nodes[id] = ClusterNode.launch(nodeConfig(id), null);
    }

    /** Stops a member (graceful close; for kill -9 use the e2e tests). */
    public void stopNode(int id) {
        CloseHelper.close(nodes[id]);
        nodes[id] = null;
    }

    public ClusterNode node(int id) {
        return nodes[id];
    }

    public Gateway startGateway(int gatewayId, int radiusPort) {
        GatewayConfig config = new GatewayConfig(
                gatewayId,
                "127.0.0.1",
                radiusPort,
                1 << 20,
                members(),
                basePort,
                "localhost",
                Profile.SMALL,
                4096,
                Duration.ofSeconds(5),
                Duration.ofSeconds(1),
                Duration.ofSeconds(30),
                false,
                Profile.SMALL.idleStrategyName(),
                new File(baseDir, "aeron/gateway-" + gatewayId).getPath(),
                null,
                Duration.ZERO);
        Gateway gateway = Gateway.launch(config, registry());
        gateways.add(gateway);
        return gateway;
    }

    public static NasRegistry registry() {
        return NasRegistry.of(List.of(new NasClient(
                NAS_NAME,
                NAS_ID,
                0x7F000001,
                32,
                SECRET.getBytes(StandardCharsets.US_ASCII),
                "default",
                NasClient.MessageAuthenticatorPolicy.OPTIONAL)));
    }

    public Gateway gateway(int index) {
        return gateways.get(index);
    }

    public List<Gateway> gateways() {
        return gateways;
    }

    /** Waits for a leader among the running members and returns it. */
    public ClusterNode awaitLeader() {
        ClusterNode[] leader = new ClusterNode[1];
        await(Duration.ofSeconds(30), "leader elected", () -> {
            for (ClusterNode n : nodes) {
                if (n != null && "LEADER".equals(n.stats().role())) {
                    leader[0] = n;
                    return true;
                }
            }
            return false;
        });
        return leader[0];
    }

    /** Waits until every gateway is connected to the cluster. */
    public void awaitGatewaysConnected() {
        await(
                Duration.ofSeconds(30),
                "gateways connected",
                () -> gateways.stream().allMatch(g -> g.stats().connected()));
    }

    /** Waits until all running members applied the same log (same applied count and digest). */
    public void awaitConverged() {
        await(Duration.ofSeconds(30), "replicas converged", () -> {
            Long digest = null;
            Long applied = null;
            for (ClusterNode n : nodes) {
                if (n == null) {
                    continue;
                }
                if (digest == null) {
                    digest = n.stats().digest();
                    applied = n.stats().applied();
                } else if (n.stats().digest() != digest || n.stats().applied() != applied) {
                    return false;
                }
            }
            return digest != null;
        });
    }

    public AdminClient admin() {
        return new AdminClient(members(), basePort);
    }

    public static void await(Duration timeout, String what, BooleanSupplier condition) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out waiting for: " + what);
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted waiting for: " + what);
            }
        }
    }

    /** A base port where every member's 6 UDP ports are free. */
    public static int freePortBase(int members) {
        for (int attempt = 0; attempt < 100; attempt++) {
            int base = 20_000 + (int) (Math.random() * 400) * 100;
            if (allFree(base, members)) {
                return base;
            }
        }
        throw new IllegalStateException("no free port range");
    }

    private static boolean allFree(int base, int members) {
        for (int i = 0; i < members; i++) {
            for (int o = 0; o < 6; o++) {
                try (DatagramSocket s = new DatagramSocket(base + 100 * i + o)) {
                    s.setReuseAddress(false);
                } catch (Exception e) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public void close() {
        gateways.forEach(CloseHelper::quietClose);
        gateways.clear();
        for (int i = 0; i < nodes.length; i++) {
            CloseHelper.quietClose(nodes[i]);
            nodes[i] = null;
        }
    }
}
