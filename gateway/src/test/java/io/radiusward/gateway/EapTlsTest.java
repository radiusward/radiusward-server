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
                Map.of(),
                Map.of(),
                Map.of(),
                new EapConfig(List.of("tls", "md5"), Duration.ofSeconds(30), 1000, 200, tls));
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
        int code = handle(h, StoreAccessHandlerTest.identity(1, identity), null);
        int rounds = 0;
        while (code == AccessHandler.CHALLENGE && rounds++ < 300) {
            EapPacket request = EapPacket.from(reply());
            assertThat(request.type()).isEqualTo(EapTls.TYPE);
            byte[] answer = client.answer(request.data());
            code = handle(h, new EapPacket(EapPacket.RESPONSE, request.identifier(), EapTls.TYPE, answer), state());
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
        byte[] msk = client.msk();
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
}
