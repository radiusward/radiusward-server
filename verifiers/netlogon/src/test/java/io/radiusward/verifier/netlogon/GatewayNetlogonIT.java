/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.Profile;
import io.radiusward.common.config.Config;
import io.radiusward.gateway.AuthConfig;
import io.radiusward.gateway.Gateway;
import io.radiusward.gateway.GatewayConfig;
import io.radiusward.gateway.NasClient;
import io.radiusward.gateway.NasRegistry;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.File;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The whole chain through a real gateway over UDP: users from the LDAP store (the domain's directory, with a group
 * policy), credentials checked by the Netlogon verifier against the domain controller.
 */
class GatewayNetlogonIT {

    static final byte[] SECRET = "testing123".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    static Path dir;

    private static Gateway gateway;

    @BeforeAll
    static void start() throws Exception {
        SambaAd.start();
        int inside =
                EndpointMapper.port(SambaAd.endpointMapper(), NetlogonClient.NETLOGON, 1, 0, SecureChannelIT.TIMEOUT);
        Map<String, String> c = new HashMap<>();
        c.put("auth.stores", "ad");
        c.put("auth.store.ad.type", "ldap");
        c.put("auth.store.ad.url", SambaAd.ldapsUrl());
        c.put("auth.store.ad.tls.ca", SambaAd.ca(dir).toString());
        c.put("auth.store.ad.bind.dn", "CN=svc-radius,CN=Users,DC=corp,DC=test");
        c.put("auth.store.ad.bind.password", "Svc-Passw0rd!");
        c.put("auth.store.ad.base.dn", "DC=corp,DC=test");
        c.put("auth.store.ad.require.groups", "VPN Users");
        c.put("auth.store.ad.policy.1.group", "Staff");
        c.put("auth.store.ad.policy.1.reply", "Filter-Id = \"staff\"");
        c.put("auth.store.ad.verifier", "dc");
        c.put("auth.verifiers", "dc");
        c.put("auth.verifier.dc.type", "netlogon");
        c.put("auth.verifier.dc.server", SambaAd.endpointMapper().getHostString());
        c.put("auth.verifier.dc.server.name", "DC");
        c.put(
                "auth.verifier.dc.netlogon.port",
                Integer.toString(SambaAd.mapped(inside).getPort()));
        c.put("auth.verifier.dc.domain", "CORP");
        c.put("auth.verifier.dc.machine.account", SambaAd.MACHINE_ACCOUNT);
        c.put("auth.verifier.dc.machine.password", SambaAd.MACHINE_PASSWORD);
        c.put("auth.plugins.dir", dir.resolve("plugins").toString());
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        GatewayConfig config = new GatewayConfig(
                1,
                "127.0.0.1",
                0,
                1 << 20,
                List.of("127.0.0.1"),
                29000,
                "localhost",
                Profile.SMALL,
                1024,
                Duration.ofSeconds(5),
                Duration.ofSeconds(1),
                Duration.ofSeconds(30),
                false,
                Profile.SMALL.idleStrategyName(),
                new File(dir.toFile(), "aeron").getPath(),
                null,
                Duration.ZERO);
        NasRegistry registry = NasRegistry.of(List.of(new NasClient(
                "local",
                1001,
                0x7F000001,
                32,
                SECRET,
                "default",
                NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                new NasClient.Identity[0],
                0,
                NasClient.MessageAuthenticatorPolicy.OFF)));
        gateway = Gateway.launchWith(config, registry, auth, Gateway.storeHandler(Config.of(c), auth));
    }

    @AfterAll
    static void stop() {
        if (gateway != null) {
            gateway.close();
        }
    }

    @Test
    void msChapV2AgainstTheDomain() throws Exception {
        byte[] authChallenge = random(16);
        byte[] peerChallenge = random(16);
        byte[] reply = send(msChap2("alice", "Alice-Passw0rd!", authChallenge, peerChallenge));
        assertThat(reply[0]).isEqualTo((byte) RadiusCode.ACCESS_ACCEPT);
        String text = new String(reply, StandardCharsets.ISO_8859_1);
        assertThat(text).as("the group policy from the directory").contains("staff");
        assertThat(text).contains(expectedSuccess("alice", "Alice-Passw0rd!", authChallenge, peerChallenge));
        assertThat(microsoft(reply, 16)).as("MS-MPPE-Send-Key").isTrue();
        assertThat(microsoft(reply, 17)).as("MS-MPPE-Recv-Key").isTrue();

        byte[] wrong = send(msChap2("alice", "wrong", random(16), random(16)));
        assertThat(wrong[0]).isEqualTo((byte) RadiusCode.ACCESS_REJECT);
        assertThat(new String(wrong, StandardCharsets.ISO_8859_1)).contains("E=691");
        assertThat(send(msChap2("bob", "Bob-Passw0rd!", random(16), random(16)))[0])
                .as("bob is not in VPN Users")
                .isEqualTo((byte) RadiusCode.ACCESS_REJECT);
    }

    // ---- an MS-CHAPv2 client --------------------------------------------------------------------

    static byte[] random(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    static byte[] challengeHash(String user, byte[] authChallenge, byte[] peerChallenge) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        sha.update(peerChallenge);
        sha.update(authChallenge);
        sha.update(user.getBytes(StandardCharsets.US_ASCII));
        return Arrays.copyOf(sha.digest(), 8);
    }

    static byte[] msChap2(String user, String password, byte[] authChallenge, byte[] peerChallenge) throws Exception {
        byte[] response = new byte[50];
        response[0] = 9;
        System.arraycopy(peerChallenge, 0, response, 2, 16);
        byte[] nt = NtResponse.of(challengeHash(user, authChallenge, peerChallenge), NetlogonCrypto.ntHash(password));
        System.arraycopy(nt, 0, response, 26, 24);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        int length = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, (int) (System.nanoTime() & 0xFF))
                .authenticator(random(16))
                .attribute(1, user)
                .vendorAttribute(311, 11, authChallenge)
                .vendorAttribute(311, 25, response)
                .finish();
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** What a client expects in MS-CHAP2-Success (RFC 2759 GenerateAuthenticatorResponse). */
    static String expectedSuccess(String user, String password, byte[] authChallenge, byte[] peerChallenge)
            throws Exception {
        byte[] hash = challengeHash(user, authChallenge, peerChallenge);
        byte[] ntHash = NetlogonCrypto.ntHash(password);
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        sha.update(Md4.digest(ntHash));
        sha.update(NtResponse.of(hash, ntHash));
        sha.update("Magic server to client signing constant".getBytes(StandardCharsets.US_ASCII));
        byte[] digest = sha.digest();
        sha.update(digest);
        sha.update(hash);
        sha.update("Pad to make it do more than one iteration".getBytes(StandardCharsets.US_ASCII));
        return "S=" + HexFormat.of().formatHex(sha.digest()).toUpperCase(Locale.ROOT);
    }

    static boolean microsoft(byte[] packet, int type) {
        ByteBuffer b = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        for (int pos = 20; pos + 2 <= packet.length; ) {
            int length = packet[pos + 1] & 0xFF;
            if (packet[pos] == 26 && b.getInt(pos + 2) == 311 && (packet[pos + 6] & 0xFF) == type) {
                return true;
            }
            pos += Math.max(length, 2);
        }
        return false;
    }

    private static byte[] send(byte[] request) throws Exception {
        try (DatagramChannel channel = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0))) {
            channel.connect(new InetSocketAddress("127.0.0.1", gateway.authPort()));
            channel.configureBlocking(false);
            ByteBuffer in = ByteBuffer.allocate(4096);
            for (int attempt = 0; attempt < 5; attempt++) {
                channel.write(ByteBuffer.wrap(request));
                long deadline = System.nanoTime() + 3_000_000_000L;
                while (System.nanoTime() < deadline) {
                    in.clear();
                    if (channel.read(in) > 0 && in.get(1) == request[1]) {
                        return Arrays.copyOf(in.array(), in.position());
                    }
                    Thread.sleep(2);
                }
            }
            throw new AssertionError("no reply");
        }
    }
}
