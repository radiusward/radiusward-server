/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.agrona.collections.IntHashSet;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** EAP-TLS (RFC 5216, RFC 9190) through the handler, with a JDK TLS client as the peer. */
class EapTlsTest {

    static final byte[] SECRET = AuthAgentTest.SECRET;

    @TempDir
    static Path dir;

    static TestPki pki;
    static TestPki other;

    private final StoreAccessHandlerTest.MemoryStore store = new StoreAccessHandlerTest.MemoryStore();
    private final AccessContext context = new AccessContext();
    private final NasClient nas = AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
            .clients()
            .iterator()
            .next();

    @BeforeAll
    static void certificates() throws Exception {
        pki = new TestPki(dir, "corp");
        other = new TestPki(dir, "other");
    }

    private StoreAccessHandler handler(int fragmentSize, boolean requireUser, int maxMessage) {
        return handler(fragmentSize, requireUser, maxMessage, List.of("tls", "md5"), Map.of(), Map.of(), Map.of());
    }

    private StoreAccessHandler handler(
            int fragmentSize,
            boolean requireUser,
            int maxMessage,
            List<String> methods,
            Map<String, Boolean> mschap,
            Map<String, io.radiusward.auth.CredentialVerifier> verifiers,
            Map<String, String> storeVerifiers) {
        EapTlsConfig tls = new EapTlsConfig(
                EapTlsConfig.context(pki.serverPem, pki.serverKey, pki.caPem),
                List.of("TLSv1.2", "TLSv1.3"),
                fragmentSize,
                maxMessage,
                requireUser);
        Map<String, IdentityStore> stores = new LinkedHashMap<>();
        stores.put("main", store);
        AuthStores auth = new AuthStores(
                stores,
                List.of("main"),
                Map.of(),
                Map.of(),
                Duration.ofSeconds(5),
                1000,
                12,
                Map.<String, IntHashSet>of(),
                mschap,
                verifiers,
                storeVerifiers,
                new EapConfig(methods, Duration.ofSeconds(30), 1000, 200, tls));
        return new StoreAccessHandler(auth, StoreAccessHandlerTest.DICTIONARY, System::currentTimeMillis);
    }

    private int handle(StoreAccessHandler h, EapPacket eap, byte[] state) {
        byte[] request = StoreAccessHandlerTest.eapRequest(eap, state);
        context.reset(new UnsafeBuffer(request), 0, request.length, nas);
        lastRequest = request;
        return h.handle(context);
    }

    private byte[] lastRequest;

    private RadiusPacket reply() {
        int length = context.replyAttributesLength();
        byte[] packet = new byte[RadiusPacket.HEADER_LENGTH + length];
        packet[0] = 2;
        packet[2] = (byte) (packet.length >> 8);
        packet[3] = (byte) packet.length;
        context.replyBuffer().getBytes(RadiusPacket.HEADER_LENGTH, packet, RadiusPacket.HEADER_LENGTH, length);
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(packet), 0, packet.length);
        return p;
    }

    private byte[] state() {
        RadiusPacket r = reply();
        int at = r.findAttribute(24);
        byte[] s = new byte[(r.buffer().getByte(at + 1) & 0xFF) - 2];
        r.buffer().getBytes(at + 2, s);
        return s;
    }

    /** Runs a whole conversation; returns the final code. */
    private int converse(StoreAccessHandler h, String identity, EapTlsClient client) throws Exception {
        return converse(h, identity, client, EapTls.TYPE);
    }

    private EapPacket lastResponse;
    private byte[] lastState;

    private int converse(StoreAccessHandler h, String identity, EapTlsClient client, int type) throws Exception {
        int code = handle(h, StoreAccessHandlerTest.identity(1, identity), null);
        int rounds = 0;
        while (code == AccessHandler.CHALLENGE && rounds++ < 300) {
            EapPacket request = EapPacket.from(reply());
            assertThat(request.type()).isEqualTo(type);
            byte[] answer = client.answer(request.data());
            lastResponse = new EapPacket(EapPacket.RESPONSE, request.identifier(), type, answer);
            lastState = state();
            code = handle(h, lastResponse, lastState);
        }
        return code;
    }

    /** RFC 2548 §2.4.2 in reverse, as a NAS does. */
    private byte[] mppe(int type) throws Exception {
        RadiusPacket p = reply();
        byte[] value = null;
        for (int pos = p.attributesOffset();
                pos < p.attributesEnd();
                pos += p.buffer().getByte(pos + 1) & 0xFF) {
            if ((p.buffer().getByte(pos) & 0xFF) == 26
                    && p.buffer().getInt(pos + 2, java.nio.ByteOrder.BIG_ENDIAN) == 311
                    && (p.buffer().getByte(pos + 6) & 0xFF) == type) {
                value = new byte[(p.buffer().getByte(pos + 7) & 0xFF) - 2];
                p.buffer().getBytes(pos + 8, value);
            }
        }
        assertThat(value).as("MS-MPPE key " + type).isNotNull();
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] plain = new byte[value.length - 2];
        byte[] previous = null;
        for (int block = 0; block < plain.length; block += 16) {
            md5.update(SECRET);
            if (previous == null) {
                md5.update(lastRequest, 4, 16);
                md5.update(value, 0, 2);
            } else {
                md5.update(previous);
            }
            byte[] b = md5.digest();
            for (int i = 0; i < 16; i++) {
                plain[block + i] = (byte) (value[2 + block + i] ^ b[i]);
            }
            previous = Arrays.copyOfRange(value, 2 + block, 2 + block + 16);
        }
        return Arrays.copyOfRange(plain, 1, 1 + plain[0]);
    }

    private void assertKeys(EapTlsClient client) throws Exception {
        assertKeys(client, EapTls.TYPE);
    }

    private void assertKeys(EapTlsClient client, int type) throws Exception {
        byte[] msk = client.msk(type);
        assertThat(mppe(17)).as("MS-MPPE-Recv-Key = MSK[0..32]").isEqualTo(Arrays.copyOfRange(msk, 0, 32));
        assertThat(mppe(16)).as("MS-MPPE-Send-Key = MSK[32..64]").isEqualTo(Arrays.copyOfRange(msk, 32, 64));
    }

    @Test
    void tls13WithAClientCertificate() throws Exception {
        store.user("alice@corp.test", List.of(), List.of(new AttributeItem("Filter-Id", "=", "staff")));
        StoreAccessHandler h = handler(1024, false, 65_536);
        EapTlsClient client =
                new EapTlsClient(TestPki.clientContext(pki.client("alice@corp.test"), pki.ca), "TLSv1.3", 1024);
        assertThat(converse(h, "alice@corp.test", client)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(EapPacket.from(reply()).code()).isEqualTo(EapPacket.SUCCESS);
        assertThat(reply().findAttribute(11))
                .as("the store's reply items still apply")
                .isPositive();
        assertKeys(client);
    }

    @Test
    void tls12AndACertificateOnlyUser() throws Exception {
        StoreAccessHandler h = handler(1024, false, 65_536);
        EapTlsClient client = new EapTlsClient(TestPki.clientContext(pki.client("device-17"), pki.ca), "TLSv1.2", 1024);
        assertThat(converse(h, "device-17", client))
                .as("in no store, but a valid certificate")
                .isEqualTo(AccessHandler.ACCEPT);
        assertKeys(client);
    }

    @Test
    void smallFragmentsBothWays() throws Exception {
        StoreAccessHandler h = handler(100, false, 65_536);
        EapTlsClient client = new EapTlsClient(TestPki.clientContext(pki.client("bob"), pki.ca), "TLSv1.3", 90);
        assertThat(converse(h, "bob", client)).isEqualTo(AccessHandler.ACCEPT);
        assertKeys(client);
    }

    @Test
    void untrustedOrMissingClientCertificatesFail() throws Exception {
        StoreAccessHandler h = handler(1024, false, 65_536);
        EapTlsClient stranger =
                new EapTlsClient(TestPki.clientContext(other.client("mallory"), pki.ca), "TLSv1.3", 1024);
        assertThat(converse(h, "mallory", stranger)).isEqualTo(AccessHandler.REJECT);
        assertThat(EapPacket.from(reply()).code()).isEqualTo(EapPacket.FAILURE);

        EapTlsClient anonymous = new EapTlsClient(TestPki.clientContext(null, pki.ca), "TLSv1.2", 1024);
        assertThat(converse(h, "nobody", anonymous)).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void requiredUsersAndMessageLimits() throws Exception {
        StoreAccessHandler strict = handler(1024, true, 65_536);
        EapTlsClient client = new EapTlsClient(TestPki.clientContext(pki.client("carol"), pki.ca), "TLSv1.3", 1024);
        assertThat(converse(strict, "carol", client)).as("not in a store").isEqualTo(AccessHandler.REJECT);

        StoreAccessHandler tiny = handler(100, false, 300);
        EapTlsClient big = new EapTlsClient(TestPki.clientContext(pki.client("dave"), pki.ca), "TLSv1.3", 90);
        assertThat(converse(tiny, "dave", big))
                .as("a message over auth.eap.tls.max.message")
                .isEqualTo(AccessHandler.REJECT);
    }

    // ---- PEAPv0 / EAP-MSCHAPv2 (ADR 0029) --------------------------------------------------------

    private StoreAccessHandler peap() {
        return peap(Map.of(), Map.of(), Map.of());
    }

    private StoreAccessHandler peap(
            Map<String, Boolean> mschap,
            Map<String, io.radiusward.auth.CredentialVerifier> verifiers,
            Map<String, String> storeVerifiers) {
        return handler(1024, false, 65_536, List.of("peap"), mschap, verifiers, storeVerifiers);
    }

    private EapTlsClient peapClient(String protocol, PeapPeer peer) throws Exception {
        return new EapTlsClient(TestPki.clientContext(null, pki.ca), protocol, 1024, peer);
    }

    @Test
    void peapTls13WithAnAnonymousOuterIdentity() throws Exception {
        store.user(
                "alice",
                List.of(new AttributeItem("NT-Password", ":=", HexFormatHolder.hex(MsChap.ntHash("Alice-Pw")))),
                List.of(new AttributeItem("Filter-Id", "=", "staff")));
        PeapPeer peer = new PeapPeer("alice", "Alice-Pw");
        EapTlsClient client = peapClient("TLSv1.3", peer);
        assertThat(converse(peap(), "anonymous@corp.test", client, Peap.TYPE)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(peer.serverProved)
                .as("the server proved it knew the password (S=)")
                .isTrue();
        assertThat(reply().findAttribute(11)).as("the inner user's reply items").isPositive();
        assertKeys(client, Peap.TYPE);
    }

    @Test
    void peapTls12WithACleartextPassword() throws Exception {
        store.user("bob", List.of(new AttributeItem("Cleartext-Password", ":=", "Bob-Pw")), List.of());
        PeapPeer peer = new PeapPeer("bob", "Bob-Pw");
        EapTlsClient client = peapClient("TLSv1.2", peer);
        assertThat(converse(peap(Map.of("main", true), Map.of(), Map.of()), "anonymous", client, Peap.TYPE))
                .isEqualTo(AccessHandler.ACCEPT);
        assertKeys(client, Peap.TYPE);
    }

    @Test
    void peapRejectsWrongPasswordsAndUnknownUsers() throws Exception {
        store.user(
                        "alice",
                        List.of(new AttributeItem("NT-Password", ":=", HexFormatHolder.hex(MsChap.ntHash("Alice-Pw")))),
                        List.of())
                .user(
                        "blocked",
                        List.of(
                                new AttributeItem("NT-Password", ":=", HexFormatHolder.hex(MsChap.ntHash("pw"))),
                                new AttributeItem("Auth-Type", ":=", "Reject")),
                        List.of());
        PeapPeer wrong = new PeapPeer("alice", "wrong");
        assertThat(converse(peap(), "anonymous", peapClient("TLSv1.3", wrong), Peap.TYPE))
                .isEqualTo(AccessHandler.REJECT);
        assertThat(wrong.failureSeen)
                .as("an MS-CHAPv2 Failure inside the tunnel first")
                .isTrue();
        assertThat(EapPacket.from(reply()).code()).isEqualTo(EapPacket.FAILURE);
        assertThat(converse(peap(), "anonymous", peapClient("TLSv1.2", new PeapPeer("nobody", "x")), Peap.TYPE))
                .isEqualTo(AccessHandler.REJECT);
        assertThat(converse(peap(), "anonymous", peapClient("TLSv1.3", new PeapPeer("blocked", "pw")), Peap.TYPE))
                .as("Auth-Type := Reject of the inner user")
                .isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void peapWithACredentialVerifierAndItsOutage() throws Exception {
        StoreAccessHandlerTest.FakeVerifier ad = new StoreAccessHandlerTest.FakeVerifier();
        store.user("User", List.of(), List.of());
        StoreAccessHandler h = peap(Map.of(), Map.of("ad", ad), Map.of("main", "ad"));
        PeapPeer peer = new PeapPeer("User", "clientPass");
        assertThat(converse(h, "anonymous", peapClient("TLSv1.3", peer), Peap.TYPE))
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(peer.serverProved).as("S= from the verifier's session key").isTrue();

        ad.down = true;
        PeapPeer again = new PeapPeer("User", "clientPass");
        assertThat(converse(h, "anonymous", peapClient("TLSv1.2", again), Peap.TYPE))
                .as("the verifier cannot answer: no answer")
                .isEqualTo(AccessHandler.DROP);
        ad.down = false;
        int code = handle(h, lastResponse, lastState); // the NAS retransmits the same request
        assertThat(code).as("the conversation waited for the retransmission").isEqualTo(AccessHandler.CHALLENGE);
    }

    /** Hex of a byte array, upper case, as NT-Password is stored. */
    static final class HexFormatHolder {
        static String hex(byte[] b) {
            return java.util.HexFormat.of().formatHex(b).toUpperCase(java.util.Locale.ROOT);
        }
    }
}
