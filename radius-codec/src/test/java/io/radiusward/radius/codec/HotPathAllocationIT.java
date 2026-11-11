/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
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
@Epic("Accounting")
@Feature("No allocation per packet")
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

    private final AccessRequests access = new AccessRequests();
    private final AccessResponses accessResponses = new AccessResponses(authenticator);
    private final UnsafeBuffer password = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
    private final UnsafeBuffer reply = new UnsafeBuffer(new byte[] {27, 6, 0, 0, 14, 16}); // Session-Timeout 3600

    /** PAP and CHAP Access-Requests (Phase 5): verify, decrypt or check, reply — no allocation. */
    @Test
    void papAndChapPathDoesNotAllocate() throws Exception {
        byte[] pap = AccessRequestsTest.request(
                AccessRequestsTest.attribute(1, "nemo".getBytes()),
                AccessRequestsTest.attribute(2, Packets.hex("0dbe708d93d413ce3196e43f782a0aee")),
                AccessRequestsTest.attribute(33, "proxy".getBytes()));
        byte[] chap = AccessRequestsTest.request(
                AccessRequestsTest.attribute(1, "nemo".getBytes()),
                AccessRequestsTest.attribute(
                        3, AccessRequestsTest.chapPassword(5, "arctangent", AccessRequestsTest.AUTHENTICATOR)));
        UnsafeBuffer papIn = new UnsafeBuffer(pap);
        UnsafeBuffer chapIn = new UnsafeBuffer(chap);
        UnsafeBuffer expected = new UnsafeBuffer("arctangent".getBytes());
        for (int i = 0; i < WARMUP; i++) {
            access(papIn, pap.length, chapIn, chap.length, expected);
        }
        long before = THREADS.getCurrentThreadAllocatedBytes();
        for (int i = 0; i < MEASURED; i++) {
            access(papIn, pap.length, chapIn, chap.length, expected);
        }
        long allocated = THREADS.getCurrentThreadAllocatedBytes() - before;
        assertThat(checksum).isNotZero();
        assertThat(allocated)
                .as(
                        "bytes allocated over %d PAP + CHAP requests (%.4f per pair)",
                        MEASURED, (double) allocated / MEASURED)
                .isLessThan(4096);
    }

    private void access(UnsafeBuffer papIn, int papLength, UnsafeBuffer chapIn, int chapLength, UnsafeBuffer expected) {
        packet.wrap(papIn, 0, papLength);
        int n = access.decryptUserPassword(packet, AccessRequestsTest.RFC_SECRET, password, 0);
        if (n != 10) {
            throw new AssertionError("PAP");
        }
        checksum += accessResponses.encode(packet, RadiusCode.ACCESS_ACCEPT, reply, 0, 6, out, 0, Packets.SECRET);
        packet.wrap(chapIn, 0, chapLength);
        if (access.method(packet) != AccessRequests.METHOD_CHAP
                || access.verifyChap(packet, expected, 0, 10) != AccessRequests.CHAP_MATCH) {
            throw new AssertionError("CHAP");
        }
        checksum += accessResponses.encode(packet, RadiusCode.ACCESS_REJECT, reply, 0, 0, out, 0, Packets.SECRET);
    }
}
