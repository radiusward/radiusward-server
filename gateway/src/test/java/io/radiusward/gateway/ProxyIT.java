/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.File;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The gateway as a proxy (ADR 0037): realms to pools of fake home servers over UDP — PAP and CHAP re-encrypted, the
 * realm stripped, Proxy-State kept for the NAS and ours removed, MS-MPPE keys re-encrypted for the NAS, Reject and
 * Challenge (EAP stays on its home server), answers without Message-Authenticator ignored, failover to the next home
 * server when one is dead and back when it answers Status-Server again; users without a proxied realm stay local.
 */
class ProxyIT {

    static final byte[] NAS_SECRET = AuthAgentTest.SECRET;

    @TempDir
    Path dir;

    private Gateway gateway;
    private FakeHomeServer a;
    private FakeHomeServer b;
    private DatagramChannel nas;
    private int identifier;

    @AfterEach
    void stop() throws Exception {
        if (gateway != null) {
            gateway.close();
        }
        for (AutoCloseable c : new AutoCloseable[] {a, b, nas}) {
            if (c != null) {
                c.close();
            }
        }
    }

    private int start(Map<String, String> extra) throws Exception {
        a = new FakeHomeServer("secret-a");
        b = new FakeHomeServer("secret-b");
        Path users = Files.writeString(dir.resolve("users"), "local-user  Cleartext-Password := \"pw\"\n");
        Map<String, String> settings = new HashMap<>(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("proxy.enabled", "true"),
                Map.entry("proxy.timeout", "200ms"),
                Map.entry("proxy.retries", "1"),
                Map.entry("proxy.dead.after", "500ms"),
                Map.entry("proxy.status.interval", "200ms"),
                Map.entry("home.a.address", "127.0.0.1:" + a.port()),
                Map.entry("home.a.secret", "secret-a"),
                Map.entry("home.b.address", "127.0.0.1:" + b.port()),
                Map.entry("home.b.secret", "secret-b"),
                Map.entry("pool.partner.servers", "a, b"),
                Map.entry("realm.partner.name", "partner.example"),
                Map.entry("realm.partner.pool", "partner")));
        settings.putAll(extra);
        Config config = Config.of(settings);
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        gateway = Gateway.launchWith(
                gatewayConfig(),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                auth,
                Gateway.storeHandler(config, auth),
                RadsecConfig.DISABLED,
                CoaConfig.DISABLED,
                ProxyConfig.from(config));
        return gateway.authPort();
    }

    /** A PAP Access-Request as a NAS sends it: Message-Authenticator, a Proxy-State of its own, a device. */
    byte[] pap(String user, String password, String device, byte[]... extra) {
        byte[] auth = new byte[16];
        ThreadLocalRandom.current().nextBytes(auth);
        byte[] plain = password.getBytes(StandardCharsets.US_ASCII);
        UnsafeBuffer cipher = new UnsafeBuffer(new byte[128]);
        int n = new AccessRequests()
                .encryptUserPassword(
                        new UnsafeBuffer(plain), 0, plain.length, new UnsafeBuffer(auth), 0, NAS_SECRET, cipher, 0);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[1024]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, ++identifier & 0xFF)
                .authenticator(auth);
        int ma = enc.messageAuthenticator();
        enc.attribute(1, user).attribute(2, cipher, 0, n).attribute(31, device).attribute(33, "nas-state");
        for (byte[] e : extra) {
            enc.rawAttribute(new UnsafeBuffer(e), 0);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signAccessRequest(buffer, 0, length, ma, NAS_SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** CHAP with the Request Authenticator as the challenge (no CHAP-Challenge). */
    byte[] chap(String user, String password) throws Exception {
        byte[] auth = new byte[16];
        ThreadLocalRandom.current().nextBytes(auth);
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update((byte) 7);
        md5.update(password.getBytes(StandardCharsets.UTF_8));
        md5.update(auth);
        byte[] response = new byte[17];
        response[0] = 7;
        System.arraycopy(md5.digest(), 0, response, 1, 16);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, ++identifier & 0xFF)
                .authenticator(auth);
        int ma = enc.messageAuthenticator();
        enc.attribute(1, user).attribute(3, response);
        int length = enc.finish();
        new RadiusAuthenticator().signAccessRequest(buffer, 0, length, ma, NAS_SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** Sends once and waits up to {@code wait} for the answer to this identifier; {@code null} if none. */
    byte[] send(int port, byte[] request, Duration wait) throws Exception {
        if (nas == null) {
            nas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
            nas.configureBlocking(false);
        }
        nas.send(ByteBuffer.wrap(request), new InetSocketAddress("127.0.0.1", port));
        ByteBuffer in = ByteBuffer.allocate(4096);
        long deadline = System.nanoTime() + wait.toNanos();
        while (System.nanoTime() < deadline) {
            in.clear();
            if (nas.receive(in) != null && in.get(1) == request[1]) {
                return Arrays.copyOf(in.array(), in.position());
            }
            Thread.sleep(2);
        }
        return null;
    }

    /** The answer's signature for the NAS, its Message-Authenticator, and the NAS's own Proxy-State only. */
    static void assertForTheNas(byte[] reply, byte[] request, int code) {
        RadiusPacket r = AuthAgentTest.wrap(reply);
        assertThat(r.code()).isEqualTo(code);
        RadiusAuthenticator a = new RadiusAuthenticator();
        assertThat(a.verifyResponse(r, new UnsafeBuffer(request), 4, NAS_SECRET))
                .as("signed for the NAS")
                .isTrue();
        assertThat(a.verifyResponseMessageAuthenticator(r, new UnsafeBuffer(request), 4, NAS_SECRET))
                .isTrue();
        assertThat(reply[20]).as("Message-Authenticator first").isEqualTo((byte) 80);
        int states = 0;
        for (int at = 20; at < reply.length; at += reply[at + 1] & 0xFF) {
            if (reply[at] == 33) {
                states++;
                assertThat(new String(reply, at + 2, (reply[at + 1] & 0xFF) - 2, StandardCharsets.US_ASCII))
                        .isEqualTo("nas-state");
            }
        }
        assertThat(states).as("the NAS's Proxy-State, not ours").isEqualTo(1);
    }

    @Test
    void papAndChapToTheHomeServerKeysForTheNas() throws Exception {
        int port = start(Map.of());
        byte[] request = pap("alice@partner.example", "secret-pw", "aa-bb-cc-00-00-01");
        byte[] reply = send(port, request, Duration.ofSeconds(3));
        assertForTheNas(reply, request, RadiusCode.ACCESS_ACCEPT);
        FakeHomeServer.Seen seen = a.requests.get(0);
        assertThat(seen.password())
                .as("re-encrypted for the home server's secret")
                .isEqualTo("secret-pw");
        assertThat(seen.user()).isEqualTo("alice@partner.example");
        assertThat(new String(reply, StandardCharsets.ISO_8859_1)).contains("home says hello");

        // MS-MPPE-Recv-Key: decrypted with the NAS's secret and the NAS's authenticator gives the home server's key
        RadiusPacket r = AuthAgentTest.wrap(reply);
        int vsa = -1;
        for (int at = r.attributesOffset(); at < r.attributesEnd(); at += reply[at + 1] & 0xFF) {
            if (reply[at] == 26) {
                vsa = at;
            }
        }
        byte[] value = Arrays.copyOfRange(reply, vsa + 8, vsa + (reply[vsa + 7] & 0xFF) + 6);
        assertThat(decryptKey(value, NAS_SECRET, Arrays.copyOfRange(request, 4, 20)))
                .isEqualTo(FakeHomeServer.MPPE_KEY);

        byte[] chap = chap("bob@partner.example", "chap-pw");
        assertForTheNasWithoutState(send(port, chap, Duration.ofSeconds(3)), chap);
        byte[] forwarded = a.requests.get(1).packet();
        RadiusPacket f = AuthAgentTest.wrap(forwarded);
        int challenge = f.findAttribute(60);
        assertThat(challenge).as("CHAP-Challenge added: the old authenticator").isPositive();
        assertThat(Arrays.copyOfRange(forwarded, challenge + 2, challenge + 18))
                .isEqualTo(Arrays.copyOfRange(chap, 4, 20));

        byte[] local = pap("local-user", "pw", "aa-bb-cc-00-00-09");
        assertThat(send(port, local, Duration.ofSeconds(3))[0])
                .as("no realm: decided by the local store")
                .isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
        assertThat(a.requests).hasSize(2);
        assertThat(gateway.metrics())
                .contains("radiusward_gateway_proxy_requests_total{gateway=\"1\",home=\"a\",result=\"accepted\"} 2");
    }

    private static void assertForTheNasWithoutState(byte[] reply, byte[] request) {
        RadiusPacket r = AuthAgentTest.wrap(reply);
        assertThat(r.code()).isEqualTo(RadiusCode.ACCESS_ACCEPT);
        assertThat(new RadiusAuthenticator().verifyResponse(r, new UnsafeBuffer(request), 4, NAS_SECRET))
                .isTrue();
        assertThat(r.findAttribute(33)).as("our Proxy-State removed").isNegative();
    }

    @Test
    void rejectChallengeStripAndUnsignedAnswers() throws Exception {
        int port = start(Map.of("realm.partner.strip", "true"));
        a.mode = FakeHomeServer.Mode.REJECT;
        byte[] rejected = pap("PARTNER.EXAMPLE\\carol", "x", "aa-bb-cc-00-00-02");
        assertForTheNas(send(port, rejected, Duration.ofSeconds(3)), rejected, RadiusCode.ACCESS_REJECT);
        assertThat(a.requests.get(0).user()).as("realm stripped, prefix form").isEqualTo("carol");

        a.mode = FakeHomeServer.Mode.CHALLENGE;
        byte[] eap = pap("dave@partner.example", "x", "aa-bb-cc-00-00-03", new byte[] {79, 7, 2, 1, 0, 5, 1});
        byte[] challenge = send(port, eap, Duration.ofSeconds(3));
        assertForTheNas(challenge, eap, RadiusCode.ACCESS_CHALLENGE);
        assertThat(new String(challenge, StandardCharsets.ISO_8859_1)).contains("home-state");
        assertThat(a.requests.get(1).user()).isEqualTo("dave");

        a.mode = FakeHomeServer.Mode.NO_MESSAGE_AUTHENTICATOR;
        byte[] unsigned = pap("erin@partner.example", "x", "aa-bb-cc-00-00-04");
        assertThat(send(port, unsigned, Duration.ofSeconds(2)))
                .as("an answer without Message-Authenticator is ignored (BlastRADIUS)")
                .isNull();
    }

    @Test
    void failoverToTheNextHomeServerAndBack() throws Exception {
        int port = start(Map.of());
        a.mode = FakeHomeServer.Mode.SILENT;
        assertThat(send(port, pap("f1@partner.example", "x", "aa-bb-cc-00-00-05"), Duration.ofSeconds(1)))
                .as("a does not answer: neither does the gateway")
                .isNull();
        Thread.sleep(800); // a is dead after proxy.dead.after without an answer
        byte[] request = pap("f2@partner.example", "x", "aa-bb-cc-00-00-06");
        assertForTheNas(send(port, request, Duration.ofSeconds(3)), request, RadiusCode.ACCESS_ACCEPT);
        assertThat(b.requests).as("the next one in the pool").hasSize(1);

        a.mode = FakeHomeServer.Mode.ACCEPT; // answers Status-Server again
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (a.statusServers.get() == 0 && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        Thread.sleep(300);
        int before = a.requests.size();
        byte[] back = pap("f3@partner.example", "x", "aa-bb-cc-00-00-07");
        assertForTheNas(send(port, back, Duration.ofSeconds(3)), back, RadiusCode.ACCESS_ACCEPT);
        assertThat(a.requests).as("a is first again").hasSize(before + 1);
        assertThat(gateway.metrics()).contains("radiusward_gateway_proxy_home_alive{gateway=\"1\",home=\"a\"} 1");
    }

    @Test
    void loadBalancedPoolsKeepADeviceOnItsServer() throws Exception {
        int port = start(Map.of("pool.partner.type", "load-balance"));
        for (int i = 0; i < 4; i++) {
            for (String device : new String[] {"aa-bb-cc-00-00-10", "aa-bb-cc-00-00-11", "aa-bb-cc-00-00-12"}) {
                byte[] request = pap("lb@partner.example", "x", device);
                assertForTheNas(send(port, request, Duration.ofSeconds(3)), request, RadiusCode.ACCESS_ACCEPT);
            }
        }
        assertThat(a.requests.size() + b.requests.size()).isEqualTo(12);
        assertThat(a.requests.size() % 4).as("each device always on one server").isZero();
    }

    /** RFC 2548 §2.4.2 in reverse, as a NAS does. */
    static byte[] decryptKey(byte[] value, byte[] secret, byte[] requestAuthenticator) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] plain = new byte[value.length - 2];
        byte[] previous = null;
        for (int block = 0; block < plain.length; block += 16) {
            md5.update(secret);
            if (previous == null) {
                md5.update(requestAuthenticator);
                md5.update(value, 0, 2);
            } else {
                md5.update(previous);
            }
            byte[] d = md5.digest();
            for (int i = 0; i < 16; i++) {
                plain[block + i] = (byte) (value[2 + block + i] ^ d[i]);
            }
            previous = Arrays.copyOfRange(value, 2 + block, 2 + block + 16);
        }
        return Arrays.copyOfRange(plain, 1, 1 + plain[0]);
    }

    GatewayConfig gatewayConfig() {
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        return new GatewayConfig(
                c.gatewayId(),
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
}
