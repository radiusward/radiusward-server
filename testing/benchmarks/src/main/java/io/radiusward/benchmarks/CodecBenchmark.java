/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.benchmarks;

import io.radiusward.radius.codec.AccountingResponses;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.codec.VendorFormats;
import io.radiusward.radius.codec.attributes.AccountingAttributeExtractor;
import io.radiusward.radius.codec.attributes.AccountingFields;
import io.radiusward.radius.codec.attributes.Cisco;
import io.radiusward.radius.codec.attributes.Ietf;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.agrona.concurrent.UnsafeBuffer;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Throughput of the accounting receive path on a typical ~200 byte Cisco interim update.
 *
 * <pre>
 * ./mvnw -Pbench -pl testing/benchmarks -am package -DskipTests
 * java -jar testing/benchmarks/target/benchmarks.jar
 * </pre>
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = "--add-exports=java.base/jdk.internal.misc=ALL-UNNAMED")
public class CodecBenchmark {

    private static final byte[] SECRET = "testing123".getBytes(StandardCharsets.US_ASCII);

    private final RadiusPacket packet = new RadiusPacket();
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final AccountingResponses responses = new AccountingResponses(authenticator);
    private final AccountingFields fields = new AccountingFields();
    private final UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private AccountingAttributeExtractor extractor;
    private UnsafeBuffer in;
    private int length;

    @Setup
    public void setup() {
        extractor = new AccountingAttributeExtractor(VendorFormats.from(DictionaryLoader.loadBundled()));
        in = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        length = new RadiusPacketEncoder()
                .wrap(in, 0)
                .header(RadiusCode.ACCOUNTING_REQUEST, 1)
                .uint32(Ietf.ACCT_STATUS_TYPE, Ietf.ACCT_STATUS_TYPE_INTERIM_UPDATE)
                .attribute(Ietf.ACCT_SESSION_ID, "00000A1B")
                .attribute(Ietf.USER_NAME, "user1@isp.example")
                .ipv4(Ietf.NAS_IP_ADDRESS, 0xC0000201L)
                .ipv4(Ietf.FRAMED_IP_ADDRESS, 0x6440000AL)
                .uint32(Ietf.ACCT_SESSION_TIME, 300)
                .uint32(Ietf.ACCT_INPUT_OCTETS, 1_048_576)
                .uint32(Ietf.ACCT_OUTPUT_OCTETS, 52_428_800)
                .uint32(Ietf.ACCT_INPUT_PACKETS, 2048)
                .uint32(Ietf.ACCT_OUTPUT_PACKETS, 40_000)
                .uint32(Ietf.EVENT_TIMESTAMP, 1_780_000_300L)
                .vendorAttribute(Cisco.VENDOR_ID, Cisco.AVPAIR, "connect-progress=LAN Ses Up")
                .vendorAttribute(Cisco.VENDOR_ID, Cisco.AVPAIR, "client-mac-address=aabb.cc00.0101")
                .finish();
        authenticator.signAccountingRequest(in, 0, length, -1, SECRET);
    }

    @Benchmark
    public int validate() {
        packet.wrap(in, 0, length);
        return packet.length();
    }

    @Benchmark
    public boolean verifyAuthenticator() {
        packet.wrap(in, 0, length);
        return authenticator.verifyAccountingRequest(packet, SECRET);
    }

    @Benchmark
    public long extract() {
        packet.wrap(in, 0, length);
        return extractor.extract(packet, fields).presentMask();
    }

    @Benchmark
    public int encodeResponse() {
        packet.wrap(in, 0, length);
        return responses.encode(packet, out, 0, SECRET, false);
    }

    /** Everything the gateway does per accounting packet before handing it to the cluster. */
    @Benchmark
    public int fullReceivePath() {
        packet.wrap(in, 0, length);
        if (!authenticator.verifyAccountingRequest(packet, SECRET)) {
            return -1;
        }
        extractor.extract(packet, fields);
        return responses.encode(packet, out, 0, SECRET, false);
    }
}
