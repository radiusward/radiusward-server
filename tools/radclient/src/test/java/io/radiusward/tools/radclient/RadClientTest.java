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
import java.util.HexFormat;
import java.util.List;
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
    void anEventTimestampGivenReplacesTheDefault() throws IOException {
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
                    "late",
                    "--attr",
                    "Event-Timestamp=1780000000");
            assertThat(code).as(err()).isEqualTo(RadClient.EXIT_OK);
            assertThat(out().split("Event-Timestamp = ", -1)).as("exactly one").hasSize(2);
            assertThat(out()).contains("(1780000000)");
        }
    }

    @Test
    void wifiPresetsIncludingOpenMeshsEmptyNasIdentifier() throws IOException {
        for (String vendor : List.of("aruba", "ubiquiti", "open-mesh", "mikrotik-hotspot")) {
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
                        "s-" + vendor,
                        "--vendor",
                        vendor);
                assertThat(code).as(vendor + ": " + err()).isEqualTo(RadClient.EXIT_OK);
            }
        }
        assertThat(out())
                .contains("Aruba.Location-Id = \"lobby-ap\"")
                .contains("Called-Station-Id = \"F0-9F-C2-11-22-33:Corp\"")
                .contains("Called-Station-Id = \"AC-86-74-12-34-56:OpenMesh-Guest\"")
                .contains("Mikrotik.Host-IP = 10.5.50.2");
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
    void decodeAsAnonymisedFixture() {
        byte[] packet = new PacketBuilder(DictionaryLoader.loadBundled(), 7)
                .add("Acct-Status-Type", "Start")
                .add("User-Name", "alice@corp.example")
                .add("NAS-IP-Address", "10.1.2.3")
                .add("Framed-IP-Address", "100.70.1.1")
                .add("Calling-Station-Id", "AA:BB:CC:00:11:22")
                .add("Event-Timestamp", "1780000000")
                .add("Cisco.AVPair", "client-mac-address=aabb.cc00.1122 ip=10.1.2.3")
                .build("s".getBytes(StandardCharsets.US_ASCII));
        String hex = HexFormat.of().formatHex(packet);

        assertThat(run("decode", hex, "--fixture", "--comment", "Cisco ASR 1000, IOS-XE 17.9: start"))
                .as(err())
                .isEqualTo(RadClient.EXIT_OK);
        assertThat(out())
                .contains("# Cisco ASR 1000, IOS-XE 17.9: start")
                .contains("identifier: 7")
                .contains("  Acct-Status-Type: Start")
                .contains("  User-Name: alice@corp.example")
                .contains("  Event-Timestamp: 1780000000")
                .doesNotContain("\npacket:");

        out.reset();
        assertThat(run("decode", hex, "--fixture", "--anonymise")).isEqualTo(RadClient.EXIT_OK);
        assertThat(out())
                .contains("anonymised")
                .contains("  User-Name: user1@example.net")
                .contains("  NAS-IP-Address: 192.0.2.1")
                .contains("  Framed-IP-Address: 192.0.2.2")
                .contains("  Calling-Station-Id: 02:00:00:00:00:01")
                // same IP, same replacement; a MAC in another notation is a different string
                .contains("  Cisco.AVPair: client-mac-address=0200.0000.0002 ip=192.0.2.1")
                .doesNotContain("alice")
                .doesNotContain("10.1.2.3")
                .doesNotContain("AA:BB");
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
        assertThat(PacketBuilder.encode(dictionary.require("Framed-IPv6-Prefix"), "2001:db8::/64"))
                .as("RFC 3162 prefixes")
                .containsExactly(0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0);
        assertThatThrownBy(() -> PacketBuilder.encode(dictionary.require("Framed-IPv6-Prefix"), "2001:db8::"))
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> new PacketBuilder(dictionary, 1).add("Frag-Status=1"))
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> new PacketBuilder(dictionary, 1).add("NoEquals"))
                .isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> new PacketBuilder(dictionary, 1).add("USR.Last-Number-Dialed-Out=1"))
                .isInstanceOf(UsageException.class);
    }

    @Test
    void authAcceptsTheRightPasswordWithEveryMethod() throws IOException {
        try (LoopbackResponder server = new LoopbackResponder(SECRET, 0, "s3cret")) {
            for (String method : List.of("pap", "chap", "mschapv2")) {
                assertThat(run(
                                "auth",
                                "--server",
                                server.address(),
                                "--secret",
                                "testing123",
                                "--user",
                                "CORP\\alice",
                                "--password",
                                "s3cret",
                                "--method",
                                method,
                                "--calling-station-id",
                                "02-00-00-00-00-01",
                                "--timeout",
                                "1s"))
                        .as(method)
                        .isEqualTo(RadClient.EXIT_OK);
                assertThat(run(
                                "auth",
                                "--server",
                                server.address(),
                                "--secret",
                                "testing123",
                                "--user",
                                "alice",
                                "--password",
                                "wrong",
                                "--method",
                                method,
                                "--timeout",
                                "1s"))
                        .as(method + ", wrong password")
                        .isEqualTo(RadClient.EXIT_NOT_ACCEPTED);
            }
        }
        assertThat(out())
                .contains("Access-Request")
                .contains("Access-Accept")
                .contains("Access-Reject")
                .contains("Response authenticator OK");
        assertThat(run(
                        "auth",
                        "--server",
                        "127.0.0.1:1",
                        "--secret",
                        "s",
                        "--user",
                        "a",
                        "--password",
                        "p",
                        "--method",
                        "eap"))
                .isEqualTo(RadClient.EXIT_USAGE);
        assertThat(run("auth", "--server", "127.0.0.1:1", "--secret", "s", "--user", "a"))
                .isEqualTo(RadClient.EXIT_USAGE);
        assertThat(err()).contains("--password is required");
        assertThat(RadClient.Options.parse(new String[] {"auth", "--server", "example.org"})
                        .server()
                        .getPort())
                .as("the authentication port by default")
                .isEqualTo(1812);
    }

    @Test
    void msChapV2NtResponseMatchesRfc2759() {
        // RFC 2759 §9.2
        HexFormat hex = HexFormat.of();
        assertThat(AccessCredentials.md4("clientPass".getBytes(StandardCharsets.UTF_16LE)))
                .isEqualTo(hex.parseHex("44ebba8d5312b8d611474411f56989ae"));
        assertThat(AccessCredentials.ntResponse(
                        hex.parseHex("5b5d7c7d7b3f2f3e3c2c602132262628"),
                        hex.parseHex("21402324255e262a28295f2b3a337c7e"),
                        "User",
                        "clientPass"))
                .isEqualTo(hex.parseHex("82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df"));
        assertThat(AccessCredentials.chapPassword(1, "p".getBytes(StandardCharsets.US_ASCII), new byte[16]))
                .hasSize(17)
                .startsWith((byte) 1);
        assertThat(AccessCredentials.Method.parse("MS-CHAPv2")).isEqualTo(AccessCredentials.Method.MSCHAPV2);
    }

    @Test
    void loadWithAnAccessRequestMix() throws IOException {
        try (LoopbackResponder accounting = new LoopbackResponder(SECRET, 0);
                LoopbackResponder access = new LoopbackResponder(SECRET, 0, "load")) {
            int code = run(
                    "load",
                    "--server",
                    accounting.address(),
                    "--secret",
                    "testing123",
                    "--sessions",
                    "5",
                    "--rate",
                    "50",
                    "--duration",
                    "1s",
                    "--interim",
                    "1s",
                    "--access-rate",
                    "60",
                    "--auth-server",
                    access.address(),
                    "--reject-ratio",
                    "0.2");
            assertThat(code).as(out() + err()).isEqualTo(RadClient.EXIT_OK);
        }
        assertThat(out())
                .containsPattern("access: sent [1-9][0-9]* \\([1-9][0-9]* with a wrong password\\)")
                .contains("timeouts 0, unexpected 0");
    }

    @Test
    void accessLoadOptions() {
        List<java.net.InetSocketAddress> accounting = List.of(new java.net.InetSocketAddress("127.0.0.1", 1813));
        assertThat(RadClient.accessLoad(RadClient.Options.parse(new String[] {"load", "--secret", "s"}), accounting))
                .as("no --access-rate: accounting only")
                .isNull();
        AccessLoad.Settings defaults = RadClient.accessLoad(
                RadClient.Options.parse(new String[] {"load", "--secret", "s", "--access-rate", "100"}), accounting);
        assertThat(defaults.servers()).containsExactly(new java.net.InetSocketAddress("127.0.0.1", 1812));
        assertThat(defaults.users()).containsExactly("load");
        assertThat(defaults.password()).isEqualTo("load");
        assertThat(defaults.methods())
                .containsExactly(
                        AccessCredentials.Method.PAP, AccessCredentials.Method.CHAP, AccessCredentials.Method.MSCHAPV2);
        assertThat(defaults.rejectRatio()).isEqualTo(0.05);
        AccessLoad.Settings given = RadClient.accessLoad(
                RadClient.Options.parse(new String[] {
                    "load", "--secret", "s", "--access-rate", "10", "--auth-server", "gw-a:11812,gw-b",
                    "--auth-users", "alice, bob", "--auth-password", "pw", "--auth-methods", "chap", "--reject-ratio",
                    "0"
                }),
                accounting);
        assertThat(given.servers())
                .extracting(java.net.InetSocketAddress::getPort)
                .containsExactly(11812, 1812);
        assertThat(given.users()).containsExactly("alice", "bob");
        assertThat(given.methods()).containsExactly(AccessCredentials.Method.CHAP);
        for (String[] bad : List.of(
                new String[] {"load", "--secret", "s", "--access-rate", "x"},
                new String[] {"load", "--secret", "s", "--access-rate", "1", "--reject-ratio", "2"},
                new String[] {"load", "--secret", "s", "--access-rate", "1", "--reject-ratio", "many"},
                new String[] {"load", "--secret", "s", "--access-rate", "1", "--auth-users", " , "},
                new String[] {"load", "--secret", "s", "--access-rate", "1", "--auth-methods", "eap"})) {
            assertThatThrownBy(() -> RadClient.accessLoad(RadClient.Options.parse(bad), accounting))
                    .isInstanceOf(UsageException.class);
        }
    }
}
