/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.aeron.Aeron;
import io.aeron.archive.client.AeronArchive;
import io.radiusward.export.AccountingSink;
import io.radiusward.export.Batch;
import io.radiusward.export.FencedException;
import io.radiusward.export.SinkContext;
import io.radiusward.protocol.LeaseResult;
import java.time.Duration;
import java.util.concurrent.locks.LockSupport;
import org.agrona.CloseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Exports one sink from this member (ADR 0017). Standby until the cluster grants this member the sink's
 * lease; then rebuilds the state-machine replica from the snapshot below the checkpoint, reads the committed
 * log, writes batches and renews the lease with each new checkpoint. A fenced write, a refused renewal or no
 * successful renewal for a lease timeout sends it back to standby.
 *
 * <p>Empty batches (the log moved only through entries without rows, such as checkpoints) are written only on
 * the renewal tick; otherwise every checkpoint would cause the next one.
 */
final class SinkRunner implements Runnable {

    private static final Logger LOG = LogManager.getLogger(SinkRunner.class);
    private static final Duration ACK_TIMEOUT = Duration.ofSeconds(3);

    private final SinkConfig config;
    private final AccountingSink sink;
    private final SinkContext context;
    private final ExporterContext exporter;
    private final int streamBase;
    private final LeaseClient lease;
    private final SinkStatus status;
    private volatile boolean running = true;

    private Aeron aeron;
    private AeronArchive archive;
    private ClusterLogReader reader;
    private StateMachineReplica replica;
    private BatchBuilder builder;
    private Batch pending;
    private boolean sinkOpen;
    private boolean owner;
    private long epoch;
    private long durablePosition;
    private long lastEventTime;
    private long batchStartedNs;
    private long nextRenewNs;
    private long lastRenewedNs;
    private long backoffMs = 100;

    SinkRunner(SinkConfig config, AccountingSink sink, SinkContext context, ExporterContext exporter, int streamBase) {
        this.config = config;
        this.sink = sink;
        this.context = context;
        this.exporter = exporter;
        this.streamBase = streamBase;
        this.lease = new LeaseClient(exporter.aeronDir(), exporter.ingressEndpoints(), exporter.egressHost());
        this.status = new SinkStatus(config.name(), config.type());
    }

    SinkStatus status() {
        return status;
    }

    void stop() {
        running = false;
    }

    @Override
    public void run() {
        try {
            aeron = Aeron.connect(new Aeron.Context().aeronDirectoryName(exporter.aeronDir()));
            archive = AeronArchive.connect(new AeronArchive.Context()
                    .aeron(aeron)
                    .controlRequestChannel(exporter.archiveControlChannel())
                    .controlRequestStreamId(AeronArchive.Configuration.localControlStreamId())
                    .controlResponseChannel(exporter.archiveControlChannel()));
            reader = new ClusterLogReader(aeron, archive, exporter.clusterDir(), streamBase);
            builder = new BatchBuilder(
                    config.name(), context.mode() == io.radiusward.export.StorageMode.SESSIONS_AND_EVENTS);
            while (running) {
                try {
                    if (!sinkOpen) {
                        sink.open(context);
                        sinkOpen = true;
                        LOG.info("sink {} ({}) open", config.name(), config.type());
                    }
                    if (owner) {
                        exportStep();
                    } else {
                        standbyStep();
                    }
                    backoffMs = 100;
                } catch (FencedException e) {
                    LOG.warn("sink {}: {}; another member exports it now", config.name(), e.getMessage());
                    loseLease();
                } catch (Exception e) {
                    status.error(e.toString());
                    LOG.error("sink {} failed, retrying in {} ms: {}", config.name(), backoffMs, e.toString());
                    closeSink();
                    sleepMs(backoffMs);
                    backoffMs = Math.min(backoffMs * 2, 30_000);
                }
            }
        } catch (RuntimeException e) {
            LOG.error("exporter for sink {} stopped", config.name(), e);
            status.error(e.toString());
        } finally {
            loseLease();
            closeSink();
            CloseHelper.quietCloseAll(lease, reader, archive, aeron);
        }
    }

    private void standbyStep() throws Exception {
        long now = System.nanoTime();
        if (now >= nextRenewNs) {
            nextRenewNs = now + renewIntervalNs();
            LeaseClient.Ack ack =
                    lease.checkpoint(config, exporter.memberId(), epoch, durablePosition, lastEventTime, ACK_TIMEOUT);
            if (ack != null) {
                status.lease(ack.owner(), ack.epoch(), ack.checkpoint(), ack.detached());
                if (ack.result() == LeaseResult.GRANTED) {
                    becomeOwner(ack);
                    return;
                }
            }
        }
        sleepMs(100);
    }

    private void becomeOwner(LeaseClient.Ack ack) throws Exception {
        epoch = ack.epoch();
        long start = Math.max(Math.max(ack.checkpoint(), sink.storedPosition()), 0);
        replica = StateMachineReplica.fromSnapshot(
                aeron, archive, exporter.clusterDir(), start, exporter.serviceSettings(), streamBase + 1, builder);
        builder.attach(replica, start);
        reader.open(replica.position());
        durablePosition = start;
        owner = true;
        lastRenewedNs = System.nanoTime();
        batchStartedNs = lastRenewedNs;
        status.owner(true, epoch, durablePosition);
        LOG.info(
                "sink {}: this member exports it now (epoch {}), from log position {} (snapshot at {})",
                config.name(),
                epoch,
                start,
                replica.position());
    }

    private void exportStep() throws Exception {
        long now = System.nanoTime();
        if (now - lastRenewedNs > config.leaseTimeoutMs() * 1_000_000L) {
            LOG.warn("sink {}: lease not renewed for {} ms; stepping back", config.name(), config.leaseTimeoutMs());
            loseLease();
            return;
        }
        if (pending != null) {
            writePending();
            return;
        }
        int fragments = 0;
        if (builder.rows() < config.batchRows()) {
            fragments = reader.poll(replica, 256);
            if (fragments > 0 && builder.rows() > 0 && batchStartedNs == 0) {
                batchStartedNs = now;
            }
        }
        boolean full = builder.rows() >= config.batchRows();
        boolean lingered = builder.rows() > 0 && now - batchStartedNs >= config.batchLingerMs() * 1_000_000L;
        if (full || lingered) {
            pending = builder.take(epoch);
            batchStartedNs = 0;
            writePending();
            return;
        }
        if (now >= nextRenewNs) {
            if (builder.rows() == 0 && builder.hasProgress()) {
                pending = builder.take(epoch); // empty batch: moves the stored position past entries without rows
                writePending();
            } else {
                renew();
            }
            return;
        }
        if (fragments == 0) {
            LockSupport.parkNanos(1_000_000);
        }
    }

    private void writePending() throws Exception {
        long started = System.nanoTime();
        sink.write(pending);
        status.batchWritten(pending.events().size() + pending.sessions().size(), System.nanoTime() - started);
        durablePosition = pending.toPosition();
        if (pending.lastEventTime() > 0) {
            lastEventTime = pending.lastEventTime();
        }
        pending = null;
        renew();
    }

    private void renew() {
        long now = System.nanoTime();
        nextRenewNs = now + renewIntervalNs();
        LeaseClient.Ack ack =
                lease.checkpoint(config, exporter.memberId(), epoch, durablePosition, lastEventTime, ACK_TIMEOUT);
        if (ack == null) {
            return; // no answer (election?); retried on the next tick, stepping back after a lease timeout
        }
        status.lease(ack.owner(), ack.epoch(), ack.checkpoint(), ack.detached());
        if (ack.result() != LeaseResult.GRANTED) {
            LOG.warn("sink {}: lease refused, member {} exports it now", config.name(), ack.owner());
            loseLease();
            return;
        }
        epoch = ack.epoch();
        lastRenewedNs = now;
        status.owner(true, epoch, durablePosition);
    }

    private long renewIntervalNs() {
        return config.leaseTimeoutMs() * 1_000_000L / 3;
    }

    private void loseLease() {
        if (owner) {
            status.owner(false, epoch, durablePosition);
        }
        owner = false;
        pending = null;
        replica = null;
        if (reader != null) {
            reader.close();
        }
    }

    private void closeSink() {
        if (sinkOpen) {
            sink.close();
            sinkOpen = false;
        }
    }

    private static void sleepMs(long ms) {
        LockSupport.parkNanos(ms * 1_000_000L);
    }
}
