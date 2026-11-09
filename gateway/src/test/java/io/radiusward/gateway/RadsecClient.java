/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** A blocking RadSec client for tests: one TLS connection, packets written and read by their length field. */
public final class RadsecClient implements AutoCloseable {

    private final SSLSocket socket;
    private final DataInputStream in;
    private final OutputStream out;

    public RadsecClient(int port, SSLContext context, String protocol) throws IOException {
        socket = (SSLSocket) context.getSocketFactory().createSocket("127.0.0.1", port);
        socket.setEnabledProtocols(new String[] {protocol});
        socket.setSoTimeout(5_000);
        socket.startHandshake();
        in = new DataInputStream(socket.getInputStream());
        out = socket.getOutputStream();
    }

    public void send(byte[] packet) throws IOException {
        out.write(packet);
        out.flush();
    }

    /** The next packet, or {@code null} when the server closed the connection. */
    public byte[] receive() throws IOException {
        byte[] header = new byte[4];
        try {
            in.readFully(header);
        } catch (EOFException e) {
            return null;
        }
        int length = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
        byte[] packet = new byte[length];
        System.arraycopy(header, 0, packet, 0, 4);
        in.readFully(packet, 4, length - 4);
        return packet;
    }

    /** Whether the server closed the connection within the socket timeout (nothing else arriving first). */
    public boolean closedByServer() throws IOException {
        try {
            return in.read() < 0;
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            return true; // reset
        }
    }

    public void timeout(int millis) throws IOException {
        socket.setSoTimeout(millis);
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
