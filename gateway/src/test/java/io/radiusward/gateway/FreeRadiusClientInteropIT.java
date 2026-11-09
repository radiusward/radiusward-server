/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.radiusward.common.config.Config;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * FreeRADIUS's own client ({@code radclient}) against a real gateway: PAP, CHAP, MS-CHAP (v1, which {@code radclient}
 * builds from {@code MS-CHAP-Password}) and Status-Server, checked by an implementation that is not ours.
 *
 * <p>Runs only with {@code -Pinterop} and when {@code radclient} is installed ({@code brew install
 * freeradius-server}); skipped otherwise.
 */
class FreeRadiusClientInteropIT {

    @TempDir
    static Path dir;

    private static Path radclient;
    private static Gateway gateway;

    @BeforeAll
    static void start() throws Exception {
        assumeTrue(Boolean.getBoolean("radiusward.interop"), "interop profile not active");
        Optional<Path> found = find("radclient");
        assumeTrue(found.isPresent(), "radclient not installed");
        radclient = found.get();

        Path users = Files.writeString(dir.resolve("users"), """
                nemo    Cleartext-Password := "arctangent"
                        Reply-Message = "Welcome"
                User    NT-Password := 44EBBA8D5312B8D611474411F56989AE
                """);
        Config stores = Config.of(Map.of(
                "auth.stores", "local",
                "auth.store.local.type", "file",
                "auth.store.local.path", users.toString(),
                "auth.store.local.chap", "true",
                "auth.store.local.mschap", "true",
                "auth.plugins.dir", dir.resolve("plugins").toString()));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        GatewayConfig base = UdpAgentTest.config(Duration.ZERO, 1024);
        GatewayConfig config = new GatewayConfig(
                base.gatewayId(),
                base.listenHost(),
                0,
                base.socketReceiveBuffer(),
                base.clusterMembers(),
                base.clusterBasePort(),
                base.egressHost(),
                base.profile(),
                base.pendingCapacity(),
                base.pendingTimeout(),
                base.resubmitAfter(),
                base.responseCacheTtl(),
                base.dedicatedThreads(),
                base.idleStrategy(),
                new File(dir.toFile(), "aeron").getPath(),
                base.dictionaryDir(),
                base.debugResponseDelay());
        gateway = Gateway.launchWith(
                config,
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                auth,
                Gateway.storeHandler(stores, auth));
    }

    @AfterAll
    static void stop() {
        if (gateway != null) {
            gateway.close();
        }
    }

    /** Runs radclient with one request; returns its output. */
    private static String radclient(String command, String request) throws Exception {
        Process process = new ProcessBuilder(
                        radclient.toString(),
                        "-x",
                        "-r",
                        "2",
                        "-t",
                        "2",
                        "127.0.0.1:" + gateway.authPort(),
                        command,
                        "testing123")
                .redirectErrorStream(true)
                .start();
        process.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
        process.getOutputStream().close();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(process.waitFor(20, TimeUnit.SECONDS)).isTrue();
        return output;
    }

    /** radclient adds and signs Message-Authenticator when the request names it. */
    private static String auth(String attributes) throws Exception {
        return radclient("auth", attributes + ", Message-Authenticator = 0x00\n");
    }

    @Test
    void pap() throws Exception {
        assertThat(auth("User-Name = \"nemo\", User-Password = \"arctangent\""))
                .contains("Received Access-Accept")
                .contains("Welcome");
        assertThat(auth("User-Name = \"nemo\", User-Password = \"wrong\"")).contains("Received Access-Reject");
    }

    @Test
    void chap() throws Exception {
        assertThat(auth("User-Name = \"nemo\", CHAP-Password = \"arctangent\"")).contains("Received Access-Accept");
        assertThat(auth("User-Name = \"nemo\", CHAP-Password = \"wrong\"")).contains("Received Access-Reject");
    }

    @Test
    void msChapFromAnNtHashAndFromCleartext() throws Exception {
        String accepted = auth("User-Name = \"User\", MS-CHAP-Password = \"clientPass\"");
        assertThat(accepted).contains("Received Access-Accept").contains("MS-CHAP-MPPE-Keys");
        assertThat(auth("User-Name = \"nemo\", MS-CHAP-Password = \"arctangent\""))
                .contains("Received Access-Accept");
        assertThat(auth("User-Name = \"User\", MS-CHAP-Password = \"other\""))
                .contains("Received Access-Reject")
                .contains("E=691");
    }

    @Test
    void statusServer() throws Exception {
        assertThat(radclient("status", "Message-Authenticator = 0x00\n")).contains("Received Access-Accept");
    }

    private static Optional<Path> find(String binary) {
        List<String> dirs = new java.util.ArrayList<>(
                List.of(System.getenv().getOrDefault("PATH", "").split(File.pathSeparator)));
        dirs.add("/opt/homebrew/bin"); // Homebrew on Apple silicon, often not on the PATH of a build
        dirs.add("/usr/local/bin");
        for (String d : dirs) {
            Path candidate = Path.of(d, binary);
            if (!d.isEmpty() && Files.isExecutable(candidate)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }
}
