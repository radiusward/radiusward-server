/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.sql;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Properties;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A small bounded JDBC pool: at most {@code size} connections, opened on demand; a borrower waits at most
 * {@code timeout} for a free one. A connection that failed is closed instead of returned, and one that sat idle is
 * checked with {@link Connection#isValid} before use. No dependency: the gateway's worker count bounds it anyway.
 */
final class ConnectionPool implements AutoCloseable {

    private final String url;
    private final Properties properties;
    private final int size;
    private final long timeoutMillis;
    private final long idleCheckNanos;
    private final ArrayBlockingQueue<Pooled> idle;
    private final AtomicInteger open = new AtomicInteger();
    private volatile boolean closed;

    record Pooled(Connection connection, long returnedAt) {}

    ConnectionPool(String url, Properties properties, int size, Duration timeout) {
        if (size < 1) {
            throw new IllegalArgumentException("pool size must be at least 1");
        }
        this.url = url;
        this.properties = properties;
        this.size = size;
        this.timeoutMillis = timeout.toMillis();
        this.idleCheckNanos = Duration.ofSeconds(30).toNanos();
        this.idle = new ArrayBlockingQueue<>(size);
    }

    /** A connection to use and then {@link #release}; waits at most the timeout. */
    Connection borrow() throws SQLException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        while (!closed) {
            Pooled pooled = idle.poll();
            if (pooled != null) {
                if (System.nanoTime() - pooled.returnedAt() < idleCheckNanos || valid(pooled.connection())) {
                    return pooled.connection();
                }
                discard(pooled.connection());
                continue;
            }
            int current = open.get();
            if (current < size && open.compareAndSet(current, current + 1)) {
                try {
                    Connection c = DriverManager.getConnection(url, properties);
                    c.setNetworkTimeout(Runnable::run, (int) timeoutMillis);
                    return c;
                } catch (SQLException | RuntimeException e) {
                    open.decrementAndGet();
                    throw e instanceof SQLException s ? s : new SQLException(e);
                }
            }
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                throw new SQLException("no free database connection within " + timeoutMillis + " ms");
            }
            try {
                pooled = idle.poll(left, TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SQLException("interrupted waiting for a database connection", e);
            }
            if (pooled != null) {
                idle.offer(pooled); // take it through the checks above
            }
        }
        throw new SQLException("connection pool closed");
    }

    /** Returns a connection; {@code broken} ones (an error happened on them) are closed instead. */
    void release(Connection connection, boolean broken) {
        if (broken || closed || !idle.offer(new Pooled(connection, System.nanoTime()))) {
            discard(connection);
        }
    }

    int open() {
        return open.get();
    }

    private static boolean valid(Connection c) {
        try {
            return c.isValid(2);
        } catch (SQLException e) {
            return false;
        }
    }

    private void discard(Connection connection) {
        open.decrementAndGet();
        try {
            connection.close();
        } catch (SQLException ignored) {
            // already broken
        }
    }

    @Override
    public void close() {
        closed = true;
        for (Pooled p = idle.poll(); p != null; p = idle.poll()) {
            discard(p.connection());
        }
    }
}
