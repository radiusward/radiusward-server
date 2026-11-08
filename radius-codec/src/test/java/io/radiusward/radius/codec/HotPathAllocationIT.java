/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.attributes.AccountingAttributeExtractor;
import io.radiusward.radius.codec.attributes.AccountingFields;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.lang.management.ManagementFactory;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/**
 * The accounting receive path must not allocate per packet: validate, verify the authenticator and
 * Message-Authenticator, extract the hot attributes and encode + sign the response.
 *
 * <p>Runs under Failsafe without the JaCoCo agent so instrumentation cannot distort the numbers.
 */
class HotPathAllocationIT {

    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    private static final int WARMUP = 200_000;
    private static final int MEASURED = 1_000_000;

    private final RadiusPacket packet = new RadiusPacket();
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final AccountingResponses responses = new AccountingResponses(authenticator);
    private final AccountingAttributeExtractor extractor =
            new AccountingAttributeExtractor(VendorFormats.from(DictionaryLoader.loadBundled()));
    private final AccountingFields fields = new AccountingFields();
    private final UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);

    private long checksum;

    @Test
    void receivePathDoesNotAllocate() {
        byte[] bytes = Packets.accountingRequest(1, true);
        UnsafeBuffer in = new UnsafeBuffer(bytes);

        for (int i = 0; i < WARMUP; i++) {
            handle(in, bytes.length);
        }
        long before = THREADS.getCurrentThreadAllocatedBytes();
        for (int i = 0; i < MEASURED; i++) {
            handle(in, bytes.length);
        }
        long allocated = THREADS.getCurrentThreadAllocatedBytes() - before;

        assertThat(checksum).isNotZero();
        // a few hundred bytes of slack for the measurement itself and JIT bookkeeping
        assertThat(allocated)
                .as("bytes allocated over %d packets (%.4f per packet)", MEASURED, (double) allocated / MEASURED)
                .isLessThan(4096);
    }

    private void handle(UnsafeBuffer in, int length) {
        if (packet.wrap(in, 0, length) != DecodeStatus.OK) {
            throw new AssertionError("invalid packet");
        }
        if (!authenticator.verifyAccountingRequest(packet, Packets.SECRET)
                || !authenticator.verifyRequestMessageAuthenticator(packet, Packets.SECRET)) {
            throw new AssertionError("authentication failed");
        }
        extractor.extract(packet, fields);
        int responseLength = responses.encode(packet, out, 0, Packets.SECRET, false);
        checksum += fields.statusType() + fields.sessionIdLength() + responseLength + out.getByte(4);
    }
}
