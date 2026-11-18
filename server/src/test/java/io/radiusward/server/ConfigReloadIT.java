/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.radius.codec.RadiusCode;
import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Reloading a running gateway (ADR 0054): a new NAS secret and another users file take effect without a restart; a
 * configuration that does not load changes nothing; the same through {@code POST /reload}.
 */
@Epic("Operations")
@Feature("Configuration reload")
@Link(
        name = "ADR 0054",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0054-config-reload.md")
class ConfigReloadIT {

    static final byte[] NEW_SECRET = "the-new-secret".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private RadiusServer radiusServer;

    @AfterEach
    void stop() {
        if (radiusServer != null) {
            radiusServer.close();
        }
    }

    private Map<String, String> config(Path users, byte[] secret) {
        Map<String, String> values = new HashMap<>();
        values.put("auth.stores", "local");
        values.put("auth.store.local.type", "file");
        values.put("auth.store.local.path", users.toString());
        values.put("auth.plugins.dir", dir.resolve("no-plugins").toString());
        values.put("nas.local.address", "127.0.0.1");
        values.put("nas.local.secret", new String(secret, StandardCharsets.US_ASCII));
        return values;
    }

    /** Whether a reply packet carries an attribute of {@code type}. */
    private static boolean hasAttribute(byte[] packet, int type) {
        int length = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
        for (int pos = 20; pos + 2 <= length; pos += packet[pos + 1] & 0xFF) {
            if ((packet[pos] & 0xFF) == type) {
                return true;
            }
            if ((packet[pos + 1] & 0xFF) < 2) {
                return false;
            }
        }
        return false;
    }

    @Test
    void secretsAndStoresChangeWithoutARestart() throws Exception {
        Path first = Files.writeString(dir.resolve("users"), "nemo    Cleartext-Password := \"arctangent\"\n");
        Path second = Files.writeString(dir.resolve("users2"), "nemo    Cleartext-Password := \"changed\"\n");
        Config config = Config.of(config(first, AuthAgentTest.SECRET));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        ServerConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        radiusServer = RadiusServer.builder(
                        new ServerConfig(
                                c.serverId(),
                                "127.0.0.1",
                                0,
                                c.socketReceiveBuffer(),
                                c.clusterMembers(),
                                c.clusterBasePort(),
                                c.egressHost(),
                                c.profile(),
                                c.pendingCapacity(),
                                c.pendingTimeout(),
                                c.resubmitAfter(),
                                c.responseCacheTtl(),
                                c.dedicatedThreads(),
                                c.idleStrategy(),
                                new File(dir.toFile(), "aeron").getPath(),
                                c.dictionaryDir(),
                                c.debugResponseDelay()),
                        NasRegistry.from(config))
                .auth(auth)
                .handlerFactory(RadiusServer.storeHandler(config, auth))
                .start();
        radiusServer.trace(config);

        byte[] request = AuthAgentTest.accessRequest(1, "arctangent", true, false);
        AuthAgentTest.assertSignedReplyTo(exchange(request), request, RadiusCode.ACCESS_ACCEPT);

        Map<String, String> broken = config(dir.resolve("missing"), NEW_SECRET);
        broken.put("auth.store.local.path", dir.resolve("missing").toString());
        broken.put("auth.totp.mode", "carrier-pigeon");
        assertThatThrownBy(() -> radiusServer.reload(Config.of(broken))).isInstanceOf(ConfigException.class);
        byte[] still = AuthAgentTest.accessRequest(2, "arctangent", true, false);
        AuthAgentTest.assertSignedReplyTo(exchange(still), still, RadiusCode.ACCESS_ACCEPT);

        assertThat(radiusServer.reload(Config.of(config(second, NEW_SECRET))))
                .contains("NAS entries: 1", "stores: local");
        byte[] changed = AuthAgentTest.accessRequest(3, "changed", true, false, NEW_SECRET);
        AuthAgentTest.assertSignedReplyTo(exchange(changed), changed, RadiusCode.ACCESS_ACCEPT, NEW_SECRET);
        byte[] old = AuthAgentTest.accessRequest(4, "arctangent", true, false, NEW_SECRET);
        AuthAgentTest.assertSignedReplyTo(exchange(old), old, RadiusCode.ACCESS_REJECT, NEW_SECRET);

        // the settings beyond the stores come with the reload too: Chargeable-User-Identity on, then off again
        assertThat(hasAttribute(exchange(AuthAgentTest.accessRequest(5, "changed", true, false, NEW_SECRET)), 89))
                .isFalse();
        Map<String, String> withCui = config(second, NEW_SECRET);
        withCui.put("auth.cui.key", "a-key-of-sixteen-chars");
        withCui.put("auth.cui.mode", "always");
        radiusServer.reload(Config.of(withCui));
        byte[] cui = exchange(AuthAgentTest.accessRequest(6, "changed", true, false, NEW_SECRET));
        assertThat(cui[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
        assertThat(hasAttribute(cui, 89))
                .as("Chargeable-User-Identity after the reload")
                .isTrue();
        radiusServer.reload(Config.of(config(second, NEW_SECRET)));
        assertThat(hasAttribute(exchange(AuthAgentTest.accessRequest(7, "changed", true, false, NEW_SECRET)), 89))
                .as("and gone after the next")
                .isFalse();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        Map<String, String> next = config(first, AuthAgentTest.SECRET);
        server.createContext(
                "/reload", new ReloadApi("a-token-of-16-chars", () -> radiusServer.reload(Config.of(next))));
        server.start();
        try (HttpClient client = HttpClient.newHttpClient()) {
            URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/reload");
            HttpRequest.Builder post = HttpRequest.newBuilder(uri)
                    .header("Authorization", "Bearer a-token-of-16-chars")
                    .POST(HttpRequest.BodyPublishers.noBody());
            assertThat(client.send(
                                    HttpRequest.newBuilder(uri)
                                            .POST(HttpRequest.BodyPublishers.noBody())
                                            .build(),
                                    HttpResponse.BodyHandlers.ofString())
                            .statusCode())
                    .isEqualTo(401);
            assertThat(client.send(
                                    HttpRequest.newBuilder(uri)
                                            .header("Authorization", "Bearer a-token-of-16-chars")
                                            .build(),
                                    HttpResponse.BodyHandlers.ofString())
                            .statusCode())
                    .isEqualTo(405);
            HttpResponse<String> ok = client.send(post.build(), HttpResponse.BodyHandlers.ofString());
            assertThat(ok.statusCode()).isEqualTo(200);
            assertThat(ok.body()).contains("\"reloaded\":\"NAS entries: 1 (were 1)");
            byte[] back = AuthAgentTest.accessRequest(5, "arctangent", true, false);
            AuthAgentTest.assertSignedReplyTo(exchange(back), back, RadiusCode.ACCESS_ACCEPT);

            next.put("auth.totp.digits", "7");
            HttpResponse<String> bad = client.send(post.build(), HttpResponse.BodyHandlers.ofString());
            assertThat(bad.statusCode()).isEqualTo(400);
            assertThat(bad.body()).contains("auth.totp.digits");
        } finally {
            server.stop(0);
        }
        assertThatThrownBy(() -> new ReloadApi("short", () -> "")).isInstanceOf(ConfigException.class);
    }

    private byte[] exchange(byte[] request) throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (DatagramSocket nas = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
            nas.setSoTimeout(3_000);
            nas.send(new DatagramPacket(request, request.length, loopback, radiusServer.authPort()));
            byte[] in = new byte[4096];
            DatagramPacket p = new DatagramPacket(in, in.length);
            nas.receive(p);
            return Arrays.copyOf(in, p.getLength());
        }
    }
}
