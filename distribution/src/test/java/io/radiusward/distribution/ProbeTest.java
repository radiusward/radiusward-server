/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.distribution;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** The container health check: 200 is healthy, anything else or nothing is not; an interrupt ends the wait. */
class ProbeTest {

    @Test
    void statusCodesAndUsage() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ready", e -> {
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            e.sendResponseHeaders(200, body.length);
            e.getResponseBody().write(body);
            e.close();
        });
        server.createContext("/down", e -> {
            e.sendResponseHeaders(503, -1);
            e.close();
        });
        server.start();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            assertThat(Probe.run(new String[] {base + "/ready"})).isZero();
            assertThat(Probe.run(new String[] {base + "/down"})).isEqualTo(1);
        } finally {
            server.stop(0);
        }
        assertThat(Probe.run(new String[0])).isEqualTo(64);
        assertThat(Probe.run(new String[] {"http://127.0.0.1:1/"}))
                .as("nothing listening")
                .isEqualTo(1);
    }

    @Test
    void anInterruptEndsTheWaitAndIsKept() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread acceptor = new Thread(() -> {
                try (Socket s = silent.accept()) {
                    s.setSoTimeout(5_000);
                    s.getInputStream().readAllBytes(); // reads the request, never answers
                } catch (Exception e) {
                    // the test is over
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            AtomicInteger result = new AtomicInteger(-1);
            AtomicBoolean stillInterrupted = new AtomicBoolean();
            Thread probe = new Thread(() -> {
                result.set(Probe.run(new String[] {"http://127.0.0.1:" + silent.getLocalPort() + "/ready"}));
                stillInterrupted.set(Thread.currentThread().isInterrupted());
            });
            long start = System.nanoTime();
            probe.start();
            Thread.sleep(300);
            probe.interrupt();
            probe.join(5_000);
            assertThat(result.get()).isEqualTo(1);
            assertThat(stillInterrupted.get())
                    .as("the interrupt flag is restored")
                    .isTrue();
            assertThat((System.nanoTime() - start) / 1_000_000)
                    .as("before the 2 s timeout")
                    .isLessThan(1_800);
        }
    }
}
