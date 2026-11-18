/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The CoA API (ADR 0036) on exchanges played by the test: the bearer token, the method, what each path takes, and how
 * the outcome of the CoA service becomes a status — 200 with one result per session, 400 for the caller's mistakes, 503
 * when the cluster does not answer, 500 for anything else.
 */
class CoaApiTest {

    static final String TOKEN = "t0ken";

    private final StoreSweepTest.Cluster cluster = new StoreSweepTest.Cluster();
    private CoaApi api;

    @AfterEach
    void close() throws Exception {
        if (api != null) {
            api.close();
        }
        cluster.close();
    }

    private static CoaService service(ClusterQueries queries) {
        return new CoaService(
                CoaConfig.DISABLED,
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF),
                queries,
                null, // the fake cluster knows no session: nothing is sent
                HandlerFixture.DICTIONARY,
                new RadsecLink(new NasClient[0]),
                Map.of(),
                Map.of(),
                null);
    }

    /** An exchange as the JDK's HTTP server hands it over; the answer completes {@link #answer}. */
    static class Exchange extends HttpExchange {
        final Headers requestHeaders = new Headers();
        final Headers responseHeaders = new Headers();
        final CompletableFuture<Answer> answer = new CompletableFuture<>();
        private final String method;
        private final URI uri;
        private final byte[] body;
        private int status = -1;
        private final ByteArrayOutputStream out = new ByteArrayOutputStream() {
            @Override
            public void close() {
                answer.complete(new Answer(status, toString(StandardCharsets.UTF_8)));
            }
        };

        Exchange(String method, String uri, String token, String body) {
            this.method = method;
            this.uri = URI.create(uri);
            this.body = body.getBytes(StandardCharsets.UTF_8);
            if (token != null) {
                requestHeaders.add("Authorization", "Bearer " + token);
            }
        }

        @Override
        public Headers getRequestHeaders() {
            return requestHeaders;
        }

        @Override
        public Headers getResponseHeaders() {
            return responseHeaders;
        }

        @Override
        public URI getRequestURI() {
            return uri;
        }

        @Override
        public String getRequestMethod() {
            return method;
        }

        @Override
        public HttpContext getHttpContext() {
            return null;
        }

        @Override
        public void close() {}

        @Override
        public InputStream getRequestBody() {
            return new ByteArrayInputStream(body);
        }

        @Override
        public OutputStream getResponseBody() {
            return out;
        }

        @Override
        public void sendResponseHeaders(int rCode, long responseLength) throws IOException {
            status = rCode;
        }

        @Override
        public InetSocketAddress getRemoteAddress() {
            return null;
        }

        @Override
        public int getResponseCode() {
            return status;
        }

        @Override
        public InetSocketAddress getLocalAddress() {
            return null;
        }

        @Override
        public String getProtocol() {
            return "HTTP/1.1";
        }

        @Override
        public Object getAttribute(String name) {
            return null;
        }

        @Override
        public void setAttribute(String name, Object value) {}

        @Override
        public void setStreams(InputStream i, OutputStream o) {}

        @Override
        public HttpPrincipal getPrincipal() {
            return null;
        }
    }

    record Answer(int status, String body) {}

    private Answer call(String method, String uri, String body) throws Exception {
        return call(new Exchange(method, uri, TOKEN, body));
    }

    private Answer call(Exchange exchange) throws Exception {
        api.handle(exchange);
        return exchange.answer.get(10, TimeUnit.SECONDS);
    }

    @Test
    void onlyPostWithTheTokenIsTakenAndEachPathChecksItsBody() throws Exception {
        api = new CoaApi(service(cluster.queries), TOKEN);
        assertThat(call(new Exchange("POST", "/coa/disconnect?user=alice", null, "")))
                .isEqualTo(new Answer(401, "{\"error\":\"missing or wrong bearer token\"}"));
        assertThat(call(new Exchange("POST", "/coa/disconnect?user=alice", "wrong", ""))
                        .status())
                .isEqualTo(401);
        assertThat(call("GET", "/coa/disconnect?user=alice", ""))
                .isEqualTo(new Answer(405, "{\"error\":\"POST expected\"}"));
        assertThat(call("POST", "/coa/update?user=alice", " \n"))
                .isEqualTo(new Answer(400, "{\"error\":\"/coa/update needs attributes in the body\"}"));
        assertThat(call("POST", "/coa/disconnect?user=alice", "Session-Timeout = 600"))
                .isEqualTo(new Answer(400, "{\"error\":\"/coa/disconnect takes no body\"}"));
        assertThat(call("POST", "/coa/disconnect?nas=local", ""))
                .as("a session needs its NAS entry and its Acct-Session-Id")
                .isEqualTo(new Answer(400, "{\"error\":\"user=<name>, or nas=<entry>&session=<Acct-Session-Id>\"}"));
        assertThat(call("POST", "/coa/disconnect?session=s-1", "").status()).isEqualTo(400);
        assertThat(cluster.usersAsked).as("none of them reached the cluster").isEmpty();
    }

    @Test
    void aUserWithoutSessionsIsAnsweredWithNone() throws Exception {
        api = new CoaApi(service(cluster.queries), TOKEN);
        assertThat(call("POST", "/coa/update?user=alice", "Session-Timeout = 600"))
                .isEqualTo(new Answer(200, "{\"sessions\":[]}"));
        assertThat(call("POST", "/coa/disconnect?user=bob", "")).isEqualTo(new Answer(200, "{\"sessions\":[]}"));
        assertThat(cluster.usersAsked).containsExactly(StoreSweepTest.userKey("alice"), StoreSweepTest.userKey("bob"));
    }

    @Test
    void aClusterThatDoesNotAnswerIs503AndAFailureIs500() throws Exception {
        cluster.fillRing();
        api = new CoaApi(service(cluster.queries), TOKEN);
        assertThat(call("POST", "/coa/disconnect?user=alice", ""))
                .isEqualTo(new Answer(503, "{\"error\":\"the cluster did not answer: query ring full\"}"));
        api.close();

        api = new CoaApi(service(null), TOKEN); // a service that fails unexpectedly
        Answer failed = call("POST", "/coa/disconnect?user=alice", "");
        assertThat(failed.status()).isEqualTo(500);
        assertThat(failed.body()).startsWith("{\"error\":\"java.lang.NullPointerException");
    }

    @Test
    void aClientGoneBeforeTheAnswerDoesNotStopTheApi() throws Exception {
        api = new CoaApi(service(cluster.queries), TOKEN);
        CompletableFuture<Void> tried = new CompletableFuture<>();
        Exchange gone = new Exchange("POST", "/coa/update?user=alice", TOKEN, "") {
            @Override
            public void sendResponseHeaders(int rCode, long responseLength) throws IOException {
                tried.complete(null);
                throw new IOException("connection reset");
            }
        };
        api.handle(gone);
        tried.get(10, TimeUnit.SECONDS);
        assertThat(gone.answer).as("nothing was answered").isNotDone();
        for (int i = 0; i < 4; i++) { // more than the API's threads: none was lost
            assertThat(call("POST", "/coa/disconnect?user=bob", "").status()).isEqualTo(200);
        }
    }

    @Test
    void resultsCarryTheErrorCauseOfANak() {
        assertThat(CoaApi.json(List.of(
                        new CoaService.SessionResult("ap", "s-1", "alice", DynamicAuthorization.Outcome.NAK, 503),
                        new CoaService.SessionResult(null, "s-2", null, DynamicAuthorization.Outcome.ACK, 0))))
                .isEqualTo("{\"sessions\":["
                        + "{\"nas\":\"ap\",\"session\":\"s-1\",\"user\":\"alice\",\"result\":\"nak\",\"errorCause\":503},"
                        + "{\"nas\":null,\"session\":\"s-2\",\"user\":null,\"result\":\"ack\"}]}");
        assertThat(CoaApi.json(List.of())).isEqualTo("{\"sessions\":[]}");
    }
}
