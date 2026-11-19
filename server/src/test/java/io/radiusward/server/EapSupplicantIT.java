/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.client.EapLogin;
import io.radiusward.client.EapResult;
import io.radiusward.client.RadiusClient;
import io.radiusward.common.config.Config;
import java.io.File;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The published EAP supplicant ({@code radiusward-client}) against the RADIUS server: every method a developer can test
 * with it is accepted for the right credential and rejected for a wrong one, the Accept's reply items arrive, and the
 * keys the device derives equal the MS-MPPE keys the server gives the NAS.
 */
@Epic("Authentication")
@Feature("EAP supplicant")
class EapSupplicantIT {

    @TempDir
    static Path dir;

    private static TestPki pki;
    private static RadiusServer server;
    private static RadiusClient client;

    @BeforeAll
    static void start() throws Exception {
        pki = new TestPki(dir, "supplicant");
        Path users = Files.writeString(dir.resolve("users"), """
                alice Cleartext-Password := "secret"
                      Class := "gold"
                """);
        Config settings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.store.local.chap", "true"),
                Map.entry("auth.store.local.mschap", "true"),
                Map.entry("auth.plugins.dir", dir.resolve("no-plugins").toString()),
                Map.entry("auth.eap.methods", "peap, ttls, tls, teap, pwd, md5"),
                Map.entry("auth.eap.teap.inner", "basic, gtc"),
                Map.entry("auth.eap.peap.inner", "mschapv2, gtc"),
                Map.entry("auth.eap.tls.certificate", pki.serverPem.toString()),
                Map.entry("auth.eap.tls.key", pki.serverKey.toString()),
                Map.entry("auth.eap.tls.ca", pki.caPem.toString()),
                Map.entry("auth.reject.delay", "0s")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        server = RadiusServer.builder(config(), AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED))
                .auth(auth)
                .handlerFactory(RadiusServer.storeHandler(settings, auth))
                .start();
        client = RadiusClient.udp(new InetSocketAddress("127.0.0.1", server.authPort()), AuthAgentTest.SECRET)
                .timeout(Duration.ofSeconds(2))
                .retries(1);
    }

    @AfterAll
    static void stop() {
        if (client != null) {
            client.close();
        }
        if (server != null) {
            server.close();
        }
    }

    private static ServerConfig config() {
        ServerConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        return new ServerConfig(
                c.serverId(),
                c.listenHost(),
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
                c.debugResponseDelay());
    }

    private static void acceptedWithKeys(EapResult r) {
        assertThat(r.accepted()).as(r.toString()).isTrue();
        assertThat(r.response().orElseThrow().string(25)).contains("gold");
        assertThat(r.msk()).as("the device's MSK").isPresent();
        assertThat(r.serverMsk()).as("what the NAS gets").isPresent();
        assertThat(r.serverMsk().orElseThrow()).isEqualTo(r.msk().orElseThrow());
    }

    @Test
    void md5() {
        EapResult ok = client.eap(EapLogin.md5("alice", "secret"));
        assertThat(ok.accepted()).isTrue();
        assertThat(ok.response().orElseThrow().string(25)).contains("gold");
        assertThat(ok.msk()).as("EAP-MD5 derives no keys").isEmpty();
        assertThat(client.eap(EapLogin.md5("alice", "wrong")).rejected()).isTrue();
    }

    @Test
    void peapWithMsChapV2IsCryptoBound() {
        EapResult r = client.eap(
                EapLogin.peap("alice", "secret").trust(pki.ca.certificate()).outerIdentity("anonymous@example.org"));
        acceptedWithKeys(r);
        assertThat(r.serverProved()).as("MS-CHAPv2's authenticator response").isTrue();
        assertThat(r.cryptoBound())
                .as("crypto-binding answered, keys from the compound session key")
                .isTrue();
        assertThat(r.rounds()).isGreaterThan(4);
        assertThat(client.eap(EapLogin.peap("alice", "wrong").trust(pki.ca.certificate()))
                        .rejected())
                .isTrue();
    }

    @Test
    void peapWithGtcAfterANak() {
        EapResult r = client.eap(EapLogin.peap("alice", "secret")
                .inner(EapLogin.Inner.GTC)
                .trust(pki.ca.certificate())
                .tlsProtocol("TLSv1.2"));
        acceptedWithKeys(r);
        assertThat(r.serverProved()).as("GTC proves nothing about the server").isFalse();
    }

    @ParameterizedTest
    @EnumSource(
            value = EapLogin.Inner.class,
            names = {"PAP", "CHAP", "MSCHAP", "MSCHAPV2"})
    void ttls(EapLogin.Inner inner) {
        EapResult r = client.eap(EapLogin.ttls("alice", "secret").inner(inner).trust(pki.ca.certificate()));
        acceptedWithKeys(r);
        assertThat(r.serverProved()).isEqualTo(inner == EapLogin.Inner.MSCHAPV2);
        assertThat(client.eap(EapLogin.ttls("alice", "wrong").inner(inner).trust(pki.ca.certificate()))
                        .rejected())
                .as(inner + " with a wrong password")
                .isTrue();
    }

    @Test
    void teapWithBasicPasswordAuthIsCryptoBound() {
        EapResult r = client.eap(EapLogin.teap("alice", "secret").trust(pki.ca.certificate()));
        acceptedWithKeys(r);
        assertThat(r.cryptoBound())
                .as("the server's Crypto-Binding checked and answered")
                .isTrue();
        assertThat(client.eap(EapLogin.teap("alice", "wrong").trust(pki.ca.certificate()))
                        .rejected())
                .isTrue();
    }

    @Test
    void teapWithAnInnerGtcAfterRefusingBasic() {
        EapResult r = client.eap(EapLogin.teap("alice", "secret")
                .inner(EapLogin.Inner.GTC)
                .trust(pki.ca.certificate())
                .tlsProtocol("TLSv1.2"));
        acceptedWithKeys(r);
        assertThat(r.cryptoBound()).isTrue();
    }

    @Test
    void pwdProvesBothSides() {
        EapResult r = client.eap(EapLogin.pwd("alice", "secret"));
        acceptedWithKeys(r);
        assertThat(r.serverProved()).as("the server's Confirm").isTrue();
        assertThatThrownBy(() -> client.eap(EapLogin.pwd("alice", "wrong")))
                .as("the server's Confirm cannot match a wrong password: the device stops")
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Confirm does not verify");
    }

    @Test
    void tlsWithAClientCertificate() throws Exception {
        TestPki.Issued laptop = pki.client("laptop-1");
        EapResult r = client.eap(EapLogin.tls("laptop-1", laptop.keys().getPrivate(), laptop.certificate())
                .trust(pki.ca.certificate())
                .fragmentSize(500));
        assertThat(r.accepted()).as(r.toString()).isTrue();
        assertThat(r.serverMsk().orElseThrow()).isEqualTo(r.msk().orElseThrow());
    }

    @Test
    void aServerOfAnotherCaIsNotTrusted() throws Exception {
        TestPki other = new TestPki(dir, "other");
        assertThatThrownBy(() -> client.eap(EapLogin.peap("alice", "secret").trust(other.ca.certificate())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("TLS");
        assertThat(client.eap(EapLogin.peap("alice", "secret").trust(pki.server.certificate()))
                        .accepted())
                .as("a server's own certificate trusted, as for a self-signed one")
                .isTrue();
        assertThatThrownBy(() -> client.eap(EapLogin.peap("alice", "secret"))).hasMessageContaining("needs trust(...)");
    }

    @Test
    void loginsAreDescribedCompletely() {
        assertThatThrownBy(() -> EapLogin.ttls("a", "b").inner(EapLogin.Inner.GTC))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EapLogin.peap("a", "b").inner(EapLogin.Inner.PAP))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EapLogin.teap("a", "b").inner(EapLogin.Inner.MSCHAPV2))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EapLogin.pwd("a", "b").inner(EapLogin.Inner.GTC))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EapLogin.md5("a", "b").fragmentSize(10)).isInstanceOf(IllegalArgumentException.class);
        assertThat(EapLogin.md5("a", "b").method()).isEqualTo(EapLogin.Method.MD5);
    }
}
