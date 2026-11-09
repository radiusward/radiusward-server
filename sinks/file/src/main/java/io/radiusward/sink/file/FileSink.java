/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.file;

import io.radiusward.export.AccountingSink;
import io.radiusward.export.Attributes;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.FencedException;
import io.radiusward.export.SessionSnapshot;
import io.radiusward.export.SinkContext;
import io.radiusward.export.StorageMode;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

/**
 * Writes JSON lines ({@code {"type":"event",...}} and {@code {"type":"session",...}}) to
 * {@code <dir>/<sink>-m<member>-<position>.jsonl}, rotated at {@code max.file.size}.
 *
 * <p>Transactional on this member: after the data is fsynced, {@code <sink>.position} records position, epoch,
 * file and length (written to a temporary file, fsynced, renamed). On open the active file is truncated to the
 * recorded length, so a batch is either completely in the file or not at all. Files land on whichever member
 * holds the sink's lease; after a lease moves, the new member's files may repeat the last batches of the old
 * one — consumers deduplicate by {@code event_id} and keep the session with the highest {@code version}.
 *
 * <p>Settings: {@code dir} (required), {@code mode} ({@code sessions} | {@code sessions+events}),
 * {@code max.file.size} (bytes, default 256 MiB).
 */
public final class FileSink implements AccountingSink {

    private SinkContext context;
    private Attributes attributes;
    private Path dir;
    private Path positionFile;
    private long maxFileSize;
    private boolean events;
    private FileChannel channel;
    private Path file;
    private long position = -1;
    private long epoch;

    @Override
    public void open(SinkContext context) throws IOException {
        this.context = context;
        this.attributes = context.attributes();
        this.dir = Path.of(context.required("dir"));
        this.maxFileSize = parseSize(context.setting("max.file.size", "256m"));
        this.events = context.mode() == StorageMode.SESSIONS_AND_EVENTS;
        Files.createDirectories(dir);
        positionFile = dir.resolve(context.name() + ".position");
        if (Files.exists(positionFile)) {
            String[] f = Files.readString(positionFile, StandardCharsets.US_ASCII)
                    .trim()
                    .split(" ");
            position = Long.parseLong(f[0]);
            epoch = Long.parseLong(f[1]);
            file = dir.resolve(f[2]);
            long length = Long.parseLong(f[3]);
            channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            if (channel.size() > length) {
                channel.truncate(length); // the tail of a batch that was never confirmed
                channel.force(true);
            }
            channel.position(length);
        }
    }

    @Override
    public CheckpointStyle checkpointStyle() {
        return CheckpointStyle.TRANSACTIONAL;
    }

    @Override
    public long storedPosition() {
        return position;
    }

    @Override
    public void write(Batch batch) throws IOException, FencedException {
        if (batch.epoch() < epoch) {
            throw new FencedException("epoch " + batch.epoch() + " < stored epoch " + epoch);
        }
        if (channel == null || channel.size() >= maxFileSize) {
            rotate(batch.fromPosition());
        }
        StringBuilder out = new StringBuilder(
                256 * (batch.events().size() + batch.sessions().size()) + 16);
        if (events) {
            for (ExportEvent e : batch.events()) {
                event(out, e);
            }
        }
        for (SessionSnapshot s : batch.sessions()) {
            session(out, s);
        }
        ByteBuffer bytes = ByteBuffer.wrap(out.toString().getBytes(StandardCharsets.UTF_8));
        while (bytes.hasRemaining()) {
            channel.write(bytes);
        }
        channel.force(true);
        String record = batch.toPosition() + " " + batch.epoch() + " " + file.getFileName() + " " + channel.position();
        Path tmp = dir.resolve(context.name() + ".position.tmp");
        try (FileChannel c = FileChannel.open(
                tmp, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            c.write(ByteBuffer.wrap(record.getBytes(StandardCharsets.US_ASCII)));
            c.force(true);
        }
        try {
            Files.move(tmp, positionFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, positionFile, StandardCopyOption.REPLACE_EXISTING);
        }
        position = batch.toPosition();
        epoch = batch.epoch();
    }

    private void rotate(long fromPosition) throws IOException {
        if (channel != null) {
            channel.close();
        }
        file = dir.resolve(context.name() + "-m" + context.memberId() + "-" + fromPosition + ".jsonl");
        channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        channel.position(channel.size());
    }

    private void event(StringBuilder out, ExportEvent e) {
        Attributes.Common common = attributes.common(e.rawAttributes());
        out.append("{\"type\":\"event\",\"event_id\":\"").append(e.eventId()).append('"');
        field(out, "log_position", e.logPosition());
        field(out, "committed_at", Instant.ofEpochMilli(e.commitTime()).toString());
        field(out, "nas_id", e.nasId());
        field(out, "nas_device", e.nasDevice());
        field(out, "gateway_id", e.gatewayId());
        field(out, "session_key", e.sessionKey() == null ? null : e.sessionKey().toString());
        field(out, "acct_session_id", e.acctSessionId());
        field(out, "status_type", e.statusType());
        field(out, "outcome", e.outcome().name().toLowerCase(java.util.Locale.ROOT));
        field(out, "session_seconds", e.sessionTime());
        field(
                out,
                "source_event_at",
                e.eventTimestamp() == null
                        ? null
                        : Instant.ofEpochSecond(e.eventTimestamp()).toString());
        field(out, "input_octets", e.inputOctets());
        field(out, "output_octets", e.outputOctets());
        common(out, common);
        field(out, "attribute_format", Attributes.JSON_FORMAT);
        String json = attributes.json(e.rawAttributes(), Attributes.COMMON);
        out.append(",\"attributes\":").append(json == null ? "null" : json).append("}\n");
    }

    private void session(StringBuilder out, SessionSnapshot s) {
        out.append("{\"type\":\"session\",\"session_key\":\"")
                .append(s.sessionKey())
                .append('"');
        field(out, "version", s.projectionVersion());
        field(out, "nas_id", s.nasId());
        field(out, "nas_device", s.nasDevice());
        field(out, "acct_session_id", s.acctSessionId());
        field(out, "state", s.state().name().toLowerCase(java.util.Locale.ROOT));
        field(out, "close_cause", s.closeCause().name().toLowerCase(java.util.Locale.ROOT));
        field(out, "status_type", s.statusType());
        field(out, "session_seconds", s.sessionTime());
        field(out, "input_octets", s.inputOctets());
        field(out, "output_octets", s.outputOctets());
        field(out, "last_received_at", Instant.ofEpochMilli(s.lastReceivedAt()).toString());
        field(
                out,
                "started_at",
                s.startedAt() == null
                        ? null
                        : Instant.ofEpochMilli(s.startedAt()).toString());
        field(
                out,
                "stopped_at",
                s.stoppedAt() == null
                        ? null
                        : Instant.ofEpochMilli(s.stoppedAt()).toString());
        if (s.rawAttributes() != null) {
            common(out, attributes.common(s.rawAttributes()));
        }
        out.append("}\n");
    }

    private static void common(StringBuilder out, Attributes.Common c) {
        field(out, "user_name", c.userName());
        field(out, "framed_ip", c.framedIp());
        field(out, "nas_ip", c.nasIp());
        field(out, "calling_station_id", c.callingStationId());
        field(out, "terminate_cause", c.terminateCause());
        field(out, "acct_multi_session_id", c.acctMultiSessionId());
    }

    private static void field(StringBuilder out, String name, Object value) {
        out.append(",\"").append(name).append("\":");
        if (value == null) {
            out.append("null");
        } else if (value instanceof Number) {
            out.append(value);
        } else {
            out.append('"');
            String s = value.toString();
            for (int i = 0; i < s.length(); i++) {
                char ch = s.charAt(i);
                switch (ch) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    default -> {
                        if (ch < 0x20) {
                            out.append(String.format("\\u%04x", (int) ch));
                        } else {
                            out.append(ch);
                        }
                    }
                }
            }
            out.append('"');
        }
    }

    private static long parseSize(String value) {
        String v = value.trim().toLowerCase(java.util.Locale.ROOT);
        long unit = v.endsWith("g") ? 1L << 30 : v.endsWith("m") ? 1L << 20 : v.endsWith("k") ? 1L << 10 : 1;
        return Long.parseLong(unit == 1 ? v : v.substring(0, v.length() - 1)) * unit;
    }

    @Override
    public void close() {
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ignored) {
                // closing after a failed write; reopening truncates to the recorded length
            }
            channel = null;
        }
    }
}
