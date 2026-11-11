/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigArgs;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Makes a member's data directory from a cluster backup (ADR 0065): copies the backup's {@code archive/} and
 * {@code cluster/} into the member's empty data directory. After a lost quorum every member is restored from the same
 * backup and started; they hold the same snapshot and log, elect a leader and go on from the backup's position.
 * The backup must be stopped while it is copied.
 *
 * <pre>radiusward cluster-restore --from &lt;backup.data.dir&gt; --config &lt;cluster.properties&gt;</pre>
 */
public final class ClusterRestore {

    private ClusterRestore() {}

    public static void main(String[] args) {
        int from = Arrays.asList(args).indexOf("--from");
        if (from < 0 || from + 1 >= args.length) {
            throw new IllegalArgumentException(
                    "usage: cluster-restore --from <backup data dir> --config <cluster.properties> [--config ...]");
        }
        Path backup = Path.of(args[from + 1]);
        String[] rest = new String[args.length - 2];
        System.arraycopy(args, 0, rest, 0, from);
        System.arraycopy(args, from + 2, rest, from, args.length - from - 2);
        Config config = Config.load(
                ConfigArgs.files(rest, "cluster-restore --from <dir> --config <file.properties>"), System.getenv());
        ClusterNodeConfig member = ClusterNodeConfig.from(config);
        long files = restore(backup, member);
        System.out.println("member " + member.nodeId() + ": " + files + " files restored from " + backup + " into "
                + member.dataDir());
    }

    /**
     * @return the number of files copied
     * @throws IllegalStateException if the member's data directory is not empty or the backup holds no snapshot
     */
    public static long restore(Path backup, ClusterNodeConfig member) {
        if (!ClusterSeed.empty(member)) {
            throw new IllegalStateException(member.dataDir() + " is not empty: move it away before restoring");
        }
        if (!Files.isRegularFile(backup.resolve("cluster").resolve("recording.log"))) {
            throw new IllegalStateException(backup + " is not a cluster backup (no cluster/recording.log)");
        }
        long copied = 0;
        for (String dir : new String[] {"archive", "cluster"}) {
            copied += copy(backup.resolve(dir), new File(member.dataDir(), dir).toPath());
        }
        // checked in the copy: Aeron opens a recording log for writing, and backups are often mounted read-only
        if (BackupProcess.latestSnapshot(new File(member.dataDir(), "cluster")) == null) {
            ClusterSeed.deleteState(member);
            throw new IllegalStateException(backup + " holds no snapshot yet: not a usable backup");
        }
        return copied;
    }

    private static long copy(Path from, Path to) {
        try (Stream<Path> files = Files.walk(from)) {
            long n = 0;
            for (Path f : (Iterable<Path>) files::iterator) {
                String name = f.getFileName().toString();
                if (name.endsWith("-mark.dat") || name.endsWith("mark-backup.dat") || name.endsWith(".lck")) {
                    continue; // mark files belong to the process that wrote them; the member creates its own
                }
                if (name.startsWith("._") || name.equals(".DS_Store")) {
                    continue; // left by macOS tools when a backup went through a Mac; a member cannot read them
                }
                Path target = to.resolve(from.relativize(f).toString());
                if (Files.isDirectory(f)) {
                    Files.createDirectories(target);
                } else {
                    Files.createDirectories(target.getParent());
                    Files.copy(f, target);
                    target.toFile().setWritable(true, true); // a member writes its files; a backup may be read-only
                    n++;
                }
            }
            return n;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
