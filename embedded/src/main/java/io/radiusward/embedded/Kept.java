/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import io.radiusward.export.AccountingSink;
import io.radiusward.export.Batch;
import io.radiusward.export.SinkContext;
import java.util.Map;
import java.util.Optional;

/**
 * Views of the developer's instances whose {@code close} does nothing: the server closes stores on a reload and the
 * exporter closes sinks when the member stops (a paused cluster), but the instance belongs to the developer and is
 * closed once, by {@link EmbeddedRadiusward#close()}.
 */
final class Kept {

    private Kept() {}

    static IdentityStore store(IdentityStore store) {
        return new IdentityStore() {
            @Override
            public Optional<UserRecord> lookup(String userName) throws StoreUnavailableException {
                return store.lookup(userName);
            }

            @Override
            public void close() {}
        };
    }

    static CredentialVerifier verifier(CredentialVerifier verifier) {
        return new CredentialVerifier() {
            @Override
            public Result verifyPassword(String userName, byte[] password) throws StoreUnavailableException {
                return verifier.verifyPassword(userName, password);
            }

            @Override
            public Result verifyMsChap(String userName, byte[] challenge, byte[] ntResponse, boolean v2)
                    throws StoreUnavailableException {
                return verifier.verifyMsChap(userName, challenge, ntResponse, v2);
            }

            @Override
            public Map<String, Long> counters() {
                return verifier.counters();
            }

            @Override
            public void close() {}
        };
    }

    static AccountingSink sink(AccountingSink sink) {
        return new AccountingSink() {
            @Override
            public void open(SinkContext context) throws Exception {
                sink.open(context);
            }

            @Override
            public CheckpointStyle checkpointStyle() {
                return sink.checkpointStyle();
            }

            @Override
            public long storedPosition() throws Exception {
                return sink.storedPosition();
            }

            @Override
            public void write(Batch batch) throws Exception {
                sink.write(batch);
            }

            @Override
            public void close() {}
        };
    }
}
