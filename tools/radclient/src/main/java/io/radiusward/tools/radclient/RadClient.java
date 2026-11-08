/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import io.radiusward.radius.dictionary.ParseMode;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Command-line RADIUS accounting client for testing radiusward (and any RADIUS server).
 *
 * <pre>
 * radclient acct   --server 127.0.0.1:1813 --secret testing123 --status start --session-id abc123
 *                  [--vendor cisco] [--user alice] [--nas-ip 192.0.2.1] [--attr Name=Value]...
 *                  [--id N] [--retries 3] [--timeout 3s] [--message-authenticator]
 * radclient replay &lt;file.fixture|file.hex&gt; --server host:port --secret s [--id N] [--retries N] [--timeout 3s]
 * radclient decode &lt;file.fixture|file.hex|hex&gt;
 * </pre>
 *
 * <p>Exit codes: 0 verified Accounting-Response, 1 no response, 2 invalid or unauthentic response,
 * 64 usage error.
 */
public final class RadClient {

    static final int EXIT_OK = 0;
    static final int EXIT_TIMEOUT = 1;
    static final int EXIT_BAD_RESPONSE = 2;
    static final int EXIT_USAGE = 64;

    /** Typical attributes per vendor, mirroring the synthetic fixtures in radius-codec. */
    static final Map<String, List<String>> VENDOR_PRESETS = Map.of(
            "cisco",
                    List.of(
                            "NAS-Port-Type=Virtual",
                            "Cisco.AVPair=connect-progress=Call Up",
                            "Cisco.NAS-Port=0/1/0/100"),
            "juniper", List.of("Service-Type=Login-User", "Juniper.Local-User-Name=super-user"),
            "juniper-erx",
                    List.of(
                            "NAS-Port-Type=Ethernet",
                            "Unisphere.Virtual-Router-Name=default:default",
                            "Unisphere.Acct-Request-Reason=Periodic"),
            "mikrotik", List.of("NAS-Port-Type=Ethernet", "NAS-Port-Id=ether2", "Mikrotik.Rate-Limit=20M/100M"),
            "huawei", List.of("NAS-Port-Type=Ethernet", "Huawei.Input-Average-Rate=20480", "Huawei.Domain-Name=isp"),
            "meraki", List.of("NAS-Port-Type=Wireless-802.11", "Meraki.Device-Name=ap-1", "Meraki.Network-Name=HQ"),
            "ruckus", List.of("NAS-Port-Type=Wireless-802.11", "Ruckus.SSID=Guest", "Ruckus.Wlan-Id=4"));

    private final PrintStream out;
    private final PrintStream err;

    RadClient(PrintStream out, PrintStream err) {
        this.out = out;
        this.err = err;
    }

    public static void main(String[] args) {
        System.exit(new RadClient(System.out, System.err).run(args));
    }

    int run(String[] args) {
        try {
            if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
                out.println(usage());
                return args.length == 0 ? EXIT_USAGE : EXIT_OK;
            }
            Options options = Options.parse(args);
            return switch (options.command) {
                case "acct" -> acct(options);
                case "replay" -> replay(options);
                case "decode" -> decode(options);
                default -> throw new UsageException("unknown command " + options.command);
            };
        } catch (UsageException e) {
            err.println("radclient: " + e.getMessage());
            err.println(usage());
            return EXIT_USAGE;
        } catch (IOException e) {
            err.println("radclient: " + e.getMessage());
            return EXIT_TIMEOUT;
        }
    }

    private int acct(Options o) throws IOException {
        Dictionary dictionary = o.dictionary();
        PacketBuilder builder = new PacketBuilder(dictionary, o.identifier());
        builder.add("Acct-Status-Type", statusName(o.required("status")));
        builder.add("Acct-Session-Id", o.required("session-id"));
        if (o.has("user")) {
            builder.add("User-Name", o.value("user"));
        }
        builder.add("NAS-IP-Address", o.value("nas-ip", "127.0.0.1"));
        builder.add("Event-Timestamp", Long.toString(System.currentTimeMillis() / 1000));
        if (o.has("vendor")) {
            List<String> preset = VENDOR_PRESETS.get(o.value("vendor").toLowerCase(Locale.ROOT));
            if (preset == null) {
                throw new UsageException(
                        "unknown vendor preset " + o.value("vendor") + "; known: " + VENDOR_PRESETS.keySet());
            }
            preset.forEach(builder::add);
        }
        o.values("attr").forEach(builder::add);
        if (o.flag("message-authenticator")) {
            builder.messageAuthenticator();
        }
        byte[] secret = o.secret();
        return exchange(o, dictionary, builder.build(secret), secret);
    }

    private int replay(Options o) throws IOException {
        Dictionary dictionary = o.dictionary();
        byte[] packet = readPacket(o.positional("file"));
        byte[] secret = o.secret();
        packet[1] = (byte) o.identifier(packet[1] & 0xFF);
        // re-sign so the packet authenticates with this secret; recompute Message-Authenticator if present
        RadiusPacket view = new RadiusPacket();
        UnsafeBuffer buffer = new UnsafeBuffer(packet);
        if (view.wrap(buffer, 0, packet.length) != DecodeStatus.OK) {
            throw new UsageException("not a valid RADIUS packet: " + view.status());
        }
        new RadiusAuthenticator()
                .signAccountingRequest(buffer, 0, view.length(), view.messageAuthenticatorOffset(), secret);
        return exchange(o, dictionary, packet, secret);
    }

    private int decode(Options o) throws IOException {
        Dictionary dictionary = o.dictionary();
        String source = o.positional("packet");
        byte[] packet = Files.exists(Path.of(source))
                ? readPacket(source)
                : HexFormat.of().parseHex(source.replaceAll("\\s+", ""));
        RadiusPacket view = new RadiusPacket();
        DecodeStatus status = view.wrap(new UnsafeBuffer(packet), 0, packet.length);
        if (status != DecodeStatus.OK) {
            err.println("invalid packet: " + status);
            return EXIT_BAD_RESPONSE;
        }
        out.print(new PacketPrinter(dictionary).print(view));
        return EXIT_OK;
    }

    private int exchange(Options o, Dictionary dictionary, byte[] request, byte[] secret) throws IOException {
        PacketPrinter printer = new PacketPrinter(dictionary);
        RadiusPacket requestView = new RadiusPacket();
        requestView.wrap(new UnsafeBuffer(request), 0, request.length);
        out.print("Sending " + printer.print(requestView));

        UdpExchange.Result result = UdpExchange.send(o.server(), request, o.retries(), o.timeout());
        if (result == null) {
            err.println("No response after " + (o.retries() + 1) + " attempt(s)");
            return EXIT_TIMEOUT;
        }
        RadiusPacket response = new RadiusPacket();
        DecodeStatus status = response.wrap(new UnsafeBuffer(result.response()), 0, result.response().length);
        if (status != DecodeStatus.OK) {
            err.println("Invalid response: " + status);
            return EXIT_BAD_RESPONSE;
        }
        out.print("Received " + printer.print(response));
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        boolean authentic =
                authenticator.verifyResponse(response, requestView.buffer(), requestView.authenticatorOffset(), secret)
                        && (!response.hasMessageAuthenticator()
                                || authenticator.verifyResponseMessageAuthenticator(
                                        response, requestView.buffer(), requestView.authenticatorOffset(), secret));
        out.printf(
                "Response authenticator %s, attempt %d, %d ms%n",
                authentic ? "OK" : "INVALID",
                result.attempts(),
                result.elapsed().toMillis());
        if (!authentic || response.code() != RadiusCode.ACCOUNTING_RESPONSE) {
            return EXIT_BAD_RESPONSE;
        }
        return EXIT_OK;
    }

    static String statusName(String status) {
        return switch (status.toLowerCase(Locale.ROOT)) {
            case "start" -> "Start";
            case "stop" -> "Stop";
            case "interim", "interim-update", "alive" -> "Interim-Update";
            case "on", "accounting-on" -> "Accounting-On";
            case "off", "accounting-off" -> "Accounting-Off";
            default -> throw new UsageException("unknown status " + status + " (start|interim|stop|on|off)");
        };
    }

    /** Reads the {@code packet:} line of a fixture, or a file containing only hex. */
    static byte[] readPacket(String file) throws IOException {
        String text = Files.readString(Path.of(file), StandardCharsets.UTF_8);
        String hex = text;
        for (String line : text.split("\n")) {
            if (line.startsWith("packet:")) {
                hex = line.substring("packet:".length());
            }
        }
        try {
            return HexFormat.of().parseHex(hex.replaceAll("(?m)#.*$", "").replaceAll("\\s+", ""));
        } catch (IllegalArgumentException e) {
            throw new UsageException(file + ": no packet hex found");
        }
    }

    static String usage() {
        return """
                usage:
                  radclient acct   --server host:port --secret s --status start|interim|stop|on|off --session-id id
                                   [--vendor cisco|juniper|juniper-erx|mikrotik|huawei|meraki|ruckus] [--user name] [--nas-ip addr]
                                   [--attr Name=Value]... [--message-authenticator]
                                   [--id n] [--retries 3] [--timeout 3s] [--dictionary-dir dir]
                  radclient replay <file.fixture|file.hex> --server host:port --secret s [--id n] [--retries n] [--timeout 3s]
                  radclient decode <file.fixture|file.hex|hex> [--dictionary-dir dir]
                exit codes: 0 verified Accounting-Response, 1 no response, 2 bad response, 64 usage error""";
    }

    /** Minimal {@code --key value} / {@code --flag} parser. */
    static final class Options {
        final String command;
        private final List<String> positional = new ArrayList<>();
        private final Map<String, List<String>> values = new java.util.HashMap<>();

        private static final List<String> FLAGS = List.of("message-authenticator");

        private Options(String command) {
            this.command = command;
        }

        static Options parse(String[] args) {
            Options o = new Options(args[0]);
            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                if (arg.startsWith("--")) {
                    String key = arg.substring(2);
                    if (FLAGS.contains(key)) {
                        o.values.computeIfAbsent(key, k -> new ArrayList<>()).add("true");
                    } else {
                        if (i + 1 >= args.length) {
                            throw new UsageException(arg + " needs a value");
                        }
                        o.values.computeIfAbsent(key, k -> new ArrayList<>()).add(args[++i]);
                    }
                } else {
                    o.positional.add(arg);
                }
            }
            return o;
        }

        boolean has(String key) {
            return values.containsKey(key);
        }

        boolean flag(String key) {
            return has(key);
        }

        String value(String key) {
            List<String> list = values.get(key);
            return list == null ? null : list.get(list.size() - 1);
        }

        String value(String key, String fallback) {
            return has(key) ? value(key) : fallback;
        }

        List<String> values(String key) {
            return values.getOrDefault(key, List.of());
        }

        String required(String key) {
            if (!has(key)) {
                throw new UsageException("--" + key + " is required");
            }
            return value(key);
        }

        String positional(String name) {
            if (positional.isEmpty()) {
                throw new UsageException("missing <" + name + ">");
            }
            return positional.get(0);
        }

        byte[] secret() {
            return required("secret").getBytes(StandardCharsets.UTF_8);
        }

        InetSocketAddress server() {
            String server = required("server");
            int colon = server.lastIndexOf(':');
            if (colon <= 0) {
                return new InetSocketAddress(server, 1813);
            }
            try {
                return new InetSocketAddress(server.substring(0, colon), Integer.parseInt(server.substring(colon + 1)));
            } catch (NumberFormatException e) {
                throw new UsageException("invalid server " + server);
            }
        }

        int identifier() {
            return identifier(ThreadLocalRandom.current().nextInt(256));
        }

        int identifier(int fallback) {
            int id = has("id") ? parseInt("id") : fallback;
            if (id < 0 || id > 255) {
                throw new UsageException("--id must be 0..255");
            }
            return id;
        }

        int retries() {
            return has("retries") ? parseInt("retries") : 3;
        }

        Duration timeout() {
            String t = value("timeout", "3s");
            try {
                if (t.endsWith("ms")) {
                    return Duration.ofMillis(Long.parseLong(t.substring(0, t.length() - 2)));
                }
                return Duration.ofMillis((long)
                        (Double.parseDouble(t.endsWith("s") ? t.substring(0, t.length() - 1) : t) * 1000));
            } catch (NumberFormatException e) {
                throw new UsageException("invalid timeout " + t);
            }
        }

        Dictionary dictionary() {
            DictionaryLoader.Builder builder = DictionaryLoader.builder().addBundledFreeRadius(ParseMode.LENIENT);
            for (String dir : values("dictionary-dir")) {
                builder.addDirectory(Path.of(dir), ParseMode.LENIENT);
            }
            return builder.load();
        }

        private int parseInt(String key) {
            try {
                return Integer.parseInt(value(key));
            } catch (NumberFormatException e) {
                throw new UsageException("--" + key + " must be a number");
            }
        }
    }
}
