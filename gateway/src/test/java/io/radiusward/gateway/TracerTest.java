/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.radius.codec.RadiusPacket;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class TracerTest {

    static final NasClient NAS = AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
            .clients()
            .iterator()
            .next();

    static RadiusPacket packet(byte[] bytes) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return p;
    }

    static RadiusPacket request(String user, String station) {
        return packet(StoreAccessHandlerTest.AccessRequestBuilder.pap(
                user,
                "very-secret-password",
                StoreAccessHandlerTest.AccessRequestBuilder.attribute(
                        31, station.getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void conditionsSelectRequestsAndSecretsStayHidden() {
        long[] now = {1000};
        Tracer tracer = new Tracer(
                StoreAccessHandlerTest.DICTIONARY,
                List.of(
                        new Tracer.Condition(Tracer.Kind.USER, "alice", Long.MAX_VALUE),
                        new Tracer.Condition(Tracer.Kind.STATION, "aabbcc", Long.MAX_VALUE)),
                () -> now[0]);
        Tracer.Trace trace = tracer.start(request("alice", "11-22"), NAS);
        assertThat(trace).isNotNull();
        assertThat(tracer.start(request("bob", "11-22"), NAS)).isNull();
        assertThat(tracer.start(request("bob", "AA:BB:CC"), NAS))
                .as("station, normalized")
                .isNotNull();

        trace.because("outside Login-Time Wk0800-1700");
        byte[] reply = new byte[RadiusPacket.HEADER_LENGTH + 7];
        reply[RadiusPacket.HEADER_LENGTH] = 18;
        reply[RadiusPacket.HEADER_LENGTH + 1] = 7;
        System.arraycopy("Hello".getBytes(StandardCharsets.US_ASCII), 0, reply, RadiusPacket.HEADER_LENGTH + 2, 5);
        String text =
                tracer.render(trace, request("alice", "11-22"), NAS, AccessHandler.REJECT, new UnsafeBuffer(reply), 7);
        assertThat(text)
                .contains("Access-Reject", "User-Name = alice", "User-Password = <", "Calling-Station-Id = 11-22")
                .contains("outside Login-Time Wk0800-1700", "reply: Reply-Message = Hello")
                .doesNotContain("very-secret", "credentials or method rejected");

        Tracer.Trace plain = tracer.start(request("alice", "x"), NAS);
        assertThat(tracer.render(plain, request("alice", "x"), NAS, AccessHandler.REJECT, new UnsafeBuffer(reply), 0))
                .contains("credentials or method rejected");
        Tracer.Trace dropped = tracer.start(request("alice", "x"), NAS);
        assertThat(tracer.render(dropped, request("alice", "x"), NAS, AccessHandler.DROP, new UnsafeBuffer(reply), 7))
                .contains("-> no answer")
                .doesNotContain("reply:");

        tracer.add(Tracer.Kind.NAS, NAS.name(), Duration.ofSeconds(10));
        assertThat(tracer.start(request("carol", "x"), NAS)).isNotNull();
        now[0] += 10_000;
        assertThat(tracer.start(request("carol", "x"), NAS)).as("expired").isNull();
        assertThat(tracer.conditions()).hasSize(2);
        tracer.clear();
        assertThat(tracer.conditions()).hasSize(2);

        Tracer none = Tracer.from(Config.of(Map.of()), StoreAccessHandlerTest.DICTIONARY);
        assertThat(none.start(request("alice", "x"), NAS)).isNull();
        Tracer configured = Tracer.from(
                Config.of(Map.of("trace.users", "alice", "trace.nas", "edge", "trace.stations", "AA-BB")),
                StoreAccessHandlerTest.DICTIONARY);
        assertThat(configured.conditions())
                .extracting(Tracer.Condition::value)
                .containsExactly("alice", "edge", "aabb");
    }

    @Test
    void theApi() throws Exception {
        Tracer tracer = Tracer.from(Config.of(Map.of()), StoreAccessHandlerTest.DICTIONARY);
        assertThatThrownBy(() -> tracer.api("short")).isInstanceOf(ConfigException.class);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/trace", tracer.api("a-token-of-16-chars"));
        server.start();
        try (HttpClient client = HttpClient.newHttpClient()) {
            String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/trace";
            java.util.function.BiFunction<String, String, HttpResponse<String>> call = (method, query) -> {
                try {
                    return client.send(
                            HttpRequest.newBuilder(URI.create(base + query))
                                    .header("Authorization", "Bearer a-token-of-16-chars")
                                    .method(method, HttpRequest.BodyPublishers.noBody())
                                    .build(),
                            HttpResponse.BodyHandlers.ofString());
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            };
            assertThat(client.send(
                                    HttpRequest.newBuilder(URI.create(base)).build(),
                                    HttpResponse.BodyHandlers.ofString())
                            .statusCode())
                    .isEqualTo(401);
            HttpResponse<String> added = call.apply("POST", "?user=alice&for=10m");
            assertThat(added.statusCode()).isEqualTo(200);
            assertThat(added.body()).contains("\"user\":\"alice\"");
            assertThat(call.apply("POST", "?station=AA-BB").body()).contains("\"station\":\"aabb\"");
            assertThat(tracer.start(request("alice", "x"), NAS)).isNotNull();
            assertThat(call.apply("GET", "").body()).contains("alice", "aabb");
            assertThat(call.apply("POST", "?user=x&for=2d").statusCode()).isEqualTo(400);
            assertThat(call.apply("POST", "?user=x&for=soon").statusCode()).isEqualTo(400);
            assertThat(call.apply("POST", "?for=1m").statusCode()).isEqualTo(400);
            assertThat(call.apply("PUT", "").statusCode()).isEqualTo(405);
            assertThat(call.apply("DELETE", "").body()).isEqualTo("{\"conditions\":[]}");
            assertThat(tracer.start(request("alice", "x"), NAS)).isNull();
        } finally {
            server.stop(0);
        }
    }
}
