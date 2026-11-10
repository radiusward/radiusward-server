/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** A DNS server for tests on a UDP port: answers NAPTR, SRV and A queries from a table (RFC 7585 discovery). */
final class TestDns implements AutoCloseable {

    static final int A = 1;
    static final int SRV = 33;
    static final int NAPTR = 35;

    private final DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
    private final Map<String, List<byte[]>> records = new ConcurrentHashMap<>();
    final AtomicInteger queries = new AtomicInteger();

    TestDns() throws Exception {
        Thread t = new Thread(this::serve, "test-dns");
        t.setDaemon(true);
        t.start();
    }

    String server() {
        return "127.0.0.1:" + socket.getLocalPort();
    }

    TestDns naptr(String name, int order, int preference, String flags, String service, String replacement) {
        ByteArrayOutputStream r = new ByteArrayOutputStream();
        short16(r, order);
        short16(r, preference);
        string(r, flags);
        string(r, service);
        string(r, "");
        name(r, replacement);
        return add(name, NAPTR, r.toByteArray());
    }

    TestDns srv(String name, int priority, int weight, int port, String target) {
        ByteArrayOutputStream r = new ByteArrayOutputStream();
        short16(r, priority);
        short16(r, weight);
        short16(r, port);
        name(r, target);
        return add(name, SRV, r.toByteArray());
    }

    TestDns a(String name, byte[] address) {
        return add(name, A, address);
    }

    private TestDns add(String name, int type, byte[] data) {
        records.computeIfAbsent(name.toLowerCase(Locale.ROOT) + "/" + type, k -> new ArrayList<>())
                .add(data);
        return this;
    }

    private void serve() {
        byte[] buffer = new byte[512];
        while (!socket.isClosed()) {
            try {
                DatagramPacket in = new DatagramPacket(buffer, buffer.length);
                socket.receive(in);
                queries.incrementAndGet();
                int at = 12;
                StringBuilder qname = new StringBuilder();
                while (buffer[at] != 0) {
                    int len = buffer[at] & 0xFF;
                    if (qname.length() > 0) {
                        qname.append('.');
                    }
                    qname.append(new String(buffer, at + 1, len, StandardCharsets.US_ASCII));
                    at += 1 + len;
                }
                at++;
                int qtype = ((buffer[at] & 0xFF) << 8) | (buffer[at + 1] & 0xFF);
                int questionEnd = at + 4;
                List<byte[]> answers =
                        records.getOrDefault(qname.toString().toLowerCase(Locale.ROOT) + "/" + qtype, List.of());
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write(buffer, 0, 2); // id
                short16(out, answers.isEmpty() ? 0x8183 : 0x8180); // response, NXDOMAIN when nothing
                short16(out, 1);
                short16(out, answers.size());
                short16(out, 0);
                short16(out, 0);
                out.write(buffer, 12, questionEnd - 12);
                for (byte[] data : answers) {
                    short16(out, 0xC00C); // the question's name
                    short16(out, qtype);
                    short16(out, 1);
                    out.writeBytes(new byte[] {0, 0, 0, 60});
                    short16(out, data.length);
                    out.writeBytes(data);
                }
                byte[] answer = out.toByteArray();
                socket.send(new DatagramPacket(answer, answer.length, in.getSocketAddress()));
            } catch (Exception e) {
                return;
            }
        }
    }

    private static void short16(ByteArrayOutputStream out, int v) {
        out.write(v >>> 8);
        out.write(v);
    }

    private static void string(ByteArrayOutputStream out, String s) {
        byte[] b = s.getBytes(StandardCharsets.US_ASCII);
        out.write(b.length);
        out.writeBytes(b);
    }

    private static void name(ByteArrayOutputStream out, String name) {
        for (String label : name.split("\\.")) {
            if (!label.isEmpty()) {
                string(out, label);
            }
        }
        out.write(0);
    }

    @Override
    public void close() {
        socket.close();
    }
}
