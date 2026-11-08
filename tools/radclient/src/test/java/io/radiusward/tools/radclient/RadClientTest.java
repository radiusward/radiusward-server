/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.radius.dictionary.DictionaryLoader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RadClientTest {

    private static final byte[] SECRET = "testing123".getBytes(StandardCharsets.US_ASCII);

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(String... args) {
        return new RadClient(
                        new PrintStream(out, true, StandardCharsets.UTF_8),
                        new PrintStream(err, true, StandardCharsets.UTF_8))
                .run(args);
    }

    private String out() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return err.toString(StandardCharsets.UTF_8);
    }

    @Test
    void accountingStartIsAnswered() throws IOException {
        try (LoopbackResponder server = new LoopbackResponder(SECRET, 0)) {
            int code = run(
                    "acct",
                    "--server",
                    server.address(),
                    "--secret",
                    "testing123",
                    "--status",
                    "start",
                    "--session-id",
                    "abc123",
                    "--user",
                    "alice",
                    "--vendor",
                    "cisco",
                    "--attr",
                    "Framed-IP-Address=100.64.0.1",
                    "--id",
                    "9",
                    "--attr",
                    "Proxy-State=0x0102");
            assertThat(code).as(err()).isEqualTo(RadClient.EXIT_OK);
            assertThat(out())
                    .contains("Sending Accounting-Request id=9")
                    .contains("Acct-Status-Type = Start")
                    .contains("Cisco.AVPair = \"connect-progress=Call Up\"")
                    .contains("Received Accounting-Response id=9")
                    .contains("Proxy-State = 0x0102")
                    .contains("Response authenticator OK, attempt 1");
        }
    }

    @Test
    void juniperErxPreset() throws IOException {
        try (LoopbackResponder server = new LoopbackResponder(SECRET, 0)) {
            int code = run(
                    "acct",
                    "--server",
                    server.address(),
                    "--secret",
                    "testing123",
                    "--status",
                    "interim",
                    "--session-id",
                    "s",
                    "--vendor",
                    "juniper-erx");
            assertThat(code).as(err()).isEqualTo(RadClient.EXIT_OK);
            assertThat(out())
                    .contains("Unisphere.Virtual-Router-Name = \"default:default\"")
                    .contains("Unisphere.Acct-Request-Reason = Periodic");
        }
    }

    @Test
    void messageAuthenticatorRoundTrip() throws IOException {
        try (LoopbackResponder server = new LoopbackResponder(SECRET, 0)) {
            int code = run(
                    "acct",
                    "--server",
                    server.address(),
                    "--secret",
                    "testing123",
                    "--status",
                    "interim",
                    "--session-id",
                    "s",
                    "--message-authenticator");
            assertThat(code).as(err()).isEqualTo(RadClient.EXIT_OK);
            assertThat(out()).contains("Message-Authenticator");
        }
    }

    @Test
    void retransmitsAfterTimeout() throws IOException {
        try (LoopbackResponder server = new LoopbackResponder(SECRET, 1)) {
            int code = run(
                    "acct",
                    "--server",
                    server.address(),
                    "--secret",
                    "testing123",
                    "--status",
                    "stop",
                    "--session-id",
                    "s",
                    "--timeout",
                    "200ms",
                    "--retries",
                    "2");
            assertThat(code).as(err()).isEqualTo(RadClient.EXIT_OK);
            assertThat(out()).contains("attempt 2");
            assertThat(server.received.get()).isEqualTo(2);
        }
    }

    @Test
    void wrongSecretMeansNoResponse() throws IOException {
        try (LoopbackResponder server = new LoopbackResponder("other".getBytes(StandardCharsets.US_ASCII), 0)) {
            int code = run(
                    "acct",
                    "--server",
                    server.address(),
                    "--secret",
                    "testing123",
                    "--status",
                    "start",
                    "--session-id",
                    "s",
                    "--timeout",
                    "100ms",
                    "--retries",
                    "1");
            assertThat(code).isEqualTo(RadClient.EXIT_TIMEOUT);
            assertThat(err()).contains("No response after 2 attempt(s)");
            assertThat(server.received.get()).isEqualTo(2);
        }
    }

    @Test
    void replayFixture(@TempDir Path dir) throws IOException {
        Path fixture =
                Files.writeString(dir.resolve("start.fixture"), """
                # comment
                identifier: 17
                packet: 04110024000000000000000000000000000000002806000000012c0a7365737369696f6e""".replace("7365737369696f6e", "73657373696f6e31"));
        try (LoopbackResponder server = new LoopbackResponder(SECRET, 0)) {
            int code = run(
                    "replay",
                    fixture.toString(),
                    "--server",
                    server.address(),
                    "--secret",
                    "testing123",
                    "--id",
                    "200");
            assertThat(code).as(err()).isEqualTo(RadClient.EXIT_OK);
            assertThat(out()).contains("Sending Accounting-Request id=200").contains("Acct-Session-Id = \"session1\"");
        }
    }

    @Test
    void decodeHexAndFile(@TempDir Path dir) throws IOException {
        String hex = "0401001a00000000000000000000000000000000280600000002";
        assertThat(run("decode", hex)).isEqualTo(RadClient.EXIT_OK);
        assertThat(out()).contains("Accounting-Request id=1 length=26").contains("Acct-Status-Type = Stop");

        Path file = Files.writeString(
                dir.resolve("p.hex"), "04 01 00 1a\n" + "00".repeat(16) + "\n28 06 00000002 # status\n");
        assertThat(run("decode", file.toString())).isEqualTo(RadClient.EXIT_OK);
        assertThat(run("decode", "0401")).isEqualTo(RadClient.EXIT_BAD_RESPONSE);
    }

    @Test
    void usageErrors() {
        assertThat(run()).isEqualTo(RadClient.EXIT_USAGE);
        assertThat(run("--help")).isEqualTo(RadClient.EXIT_OK);
        assertThat(run("frobnicate")).isEqualTo(RadClient.EXIT_USAGE);
        assertThat(run("acct", "--server", "127.0.0.1:1", "--secret", "s", "--session-id", "x"))
                .isEqualTo(RadClient.EXIT_USAGE);
        assertThat(err()).contains("--status is required");
        assertThat(run(
                        "acct",
                        "--server",
                        "127.0.0.1:1",
                        "--secret",
                        "s",
                        "--status",
                        "start",
                        "--session-id",
                        "x",
                        "--vendor",
                        "acme"))
                .isEqualTo(RadClient.EXIT_USAGE);
        assertThat(run(
                        "acct",
                        "--server",
                        "127.0.0.1:1",
                        "--secret",
                        "s",
                        "--status",
                        "start",
                        "--session-id",
                        "x",
                        "--attr",
                        "Nope=1"))
                .isEqualTo(RadClient.EXIT_USAGE);
        assertThat(run("acct", "--secret")).isEqualTo(RadClient.EXIT_USAGE);
        assertThat(run("acct", "--server", "h:x", "--secret", "s", "--status", "on", "--session-id", "x"))
                .isEqualTo(RadClient.EXIT_USAGE);
        assertThat(run(
                        "acct",
                        "--server",
                        "127.0.0.1:1",
                        "--secret",
                        "s",
                        "--status",
                        "off",
                        "--session-id",
                        "x",
                        "--id",
                        "300"))
                .isEqualTo(RadClient.EXIT_USAGE);
        assertThat(run("replay")).isEqualTo(RadClient.EXIT_USAGE);
        assertThat(err()).contains("missing <file>");
    }

    @Test
    void optionParsing() {
        RadClient.Options o = RadClient.Options.parse(
                new String[] {"acct", "--timeout", "1.5s", "--retries", "0", "--server", "example.org"});
        assertThat(o.timeout()).isEqualTo(Duration.ofMillis(1500));
        assertThat(o.retries()).isZero();
        assertThat(o.server().getPort()).isEqualTo(1813);
        assertThat(RadClient.Options.parse(new String[] {"acct", "--timeout", "250ms"})
                        .timeout())
                .isEqualTo(Duration.ofMillis(250));
        assertThat(RadClient.Options.parse(new String[] {"acct", "--timeout", "2"})
                        .timeout())
                .isEqualTo(Duration.ofSeconds(2));
        assertThatThrownBy(() -> RadClient.Options.parse(new String[] {"acct", "--timeout", "soon"})
                        .timeout())
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> RadClient.Options.parse(new String[] {"acct", "--retries", "x"})
                        .retries())
                .isInstanceOf(UsageException.class);
        assertThat(RadClient.statusName("interim-update")).isEqualTo("Interim-Update");
        assertThatThrownBy(() -> RadClient.statusName("pause")).isInstanceOf(UsageException.class);
    }

    @Test
    void packetBuilderTypes() {
        var dictionary = DictionaryLoader.loadBundled();
        assertThat(PacketBuilder.encode(dictionary.require("NAS-IPv6-Address"), "2001:db8::1"))
                .hasSize(16);
        assertThat(PacketBuilder.encode(dictionary.require("Acct-Status-Type"), "0x00000003"))
                .containsExactly(0, 0, 0, 3);
        assertThat(PacketBuilder.encode(dictionary.require("Acct-Status-Type"), "Stop"))
                .containsExactly(0, 0, 0, 2);
        assertThatThrownBy(() -> PacketBuilder.encode(dictionary.require("Acct-Status-Type"), "Sometimes"))
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> PacketBuilder.encode(dictionary.require("NAS-IP-Address"), "2001:db8::1"))
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> PacketBuilder.encode(dictionary.require("Framed-IPv6-Prefix"), "2001:db8::/64"))
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> new PacketBuilder(dictionary, 1).add("Frag-Status=1"))
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> new PacketBuilder(dictionary, 1).add("NoEquals"))
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> new PacketBuilder(dictionary, 1).add("USR.Last-Number-Dialed-Out=1"))
                .isInstanceOf(UsageException.class);
    }
}
