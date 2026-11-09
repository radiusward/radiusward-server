/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.file;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Users from a FreeRADIUS-style users file ({@code auth.store.<name>.type = file}, {@code path}); for tests, labs and
 * small sites. The file is read at start (an error stops the gateway) and re-read when it changes, checked at most
 * every {@code reload.interval} (5 s); a changed file with errors is logged and the previous users stay.
 */
final class FileStore implements IdentityStore {

    private static final Logger LOG = LogManager.getLogger(FileStore.class);

    private final Path path;
    private final long checkEveryNanos;
    private final Function<AttributeItem, String> replyCheck;
    private volatile Map<String, UserRecord> users;
    private volatile FileTime loaded;
    private volatile long nextCheck;

    FileStore(StoreContext context) {
        this.path = Path.of(context.required("path"));
        this.checkEveryNanos = context.duration("reload.interval", "5s").toNanos();
        this.replyCheck = context.replyCheck();
        try {
            this.loaded = Files.getLastModifiedTime(path);
            this.users = UsersFile.parse(Files.readAllLines(path, StandardCharsets.UTF_8), replyCheck);
        } catch (IOException e) {
            throw new IllegalArgumentException("auth.store." + context.name() + ".path: cannot read " + path, e);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(path + ": " + e.getMessage(), e);
        }
        this.nextCheck = System.nanoTime() + checkEveryNanos;
        LOG.info("identity store {}: {} users from {}", context.name(), users.size(), path);
    }

    @Override
    public Optional<UserRecord> lookup(String userName) throws StoreUnavailableException {
        long now = System.nanoTime();
        if (now - nextCheck >= 0) {
            reloadIfChanged(now);
        }
        return Optional.ofNullable(users.get(userName));
    }

    private synchronized void reloadIfChanged(long now) {
        if (now - nextCheck < 0) {
            return; // another worker just checked
        }
        nextCheck = now + checkEveryNanos;
        try {
            FileTime modified = Files.getLastModifiedTime(path);
            if (modified.equals(loaded)) {
                return;
            }
            Map<String, UserRecord> fresh =
                    UsersFile.parse(Files.readAllLines(path, StandardCharsets.UTF_8), replyCheck);
            users = fresh;
            loaded = modified;
            LOG.info("identity store: reloaded {} users from {}", fresh.size(), path);
        } catch (IOException | IllegalArgumentException e) {
            LOG.warn("identity store: {} not reloaded, keeping the previous users: {}", path, e.getMessage());
        }
    }

    @Override
    public void close() {}
}
