/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
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
        return handler(fragmentSize, requireUser, maxMessage, methods, mschap, verifiers, storeVerifiers, List.of(26));
    }

    private StoreAccessHandler handler(
            int fragmentSize,
            boolean requireUser,
            int maxMessage,
            List<String> methods,
            Map<String, Boolean> mschap,
            Map<String, io.radiusward.auth.CredentialVerifier> verifiers,
            Map<String, String> storeVerifiers,
            List<Integer> peapInner) {
        EapTlsConfig tls = tlsConfig != null
                ? tlsConfig
                : new EapTlsConfig(
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
                cacheTtl,
                1000,
                12,
                Map.<String, IntHashSet>of(),
                mschap,
                verifiers,
                storeVerifiers,
                new EapConfig(
                        methods,
                        Duration.ofSeconds(30),
                        1000,
                        200,
                        tls,
                        peapInner,
                        binding,
                        peapCertificate,
                        EapConfig.DEFAULT_TTLS_INNER));
        return new StoreAccessHandler(auth, StoreAccessHandlerTest.DICTIONARY, System::currentTimeMillis);
    }

    private int handle(StoreAccessHandler h, EapPacket eap, byte[] state) {
        byte[] request = StoreAccessHandlerTest.eapRequest(eap, state);
        context.reset(new UnsafeBuffer(request), 0, request.length, nas);
        lastRequest = request;
        return h.handle(context);
    }

    private byte[] lastRequest;
    private Peap.Binding binding = Peap.Binding.OPTIONAL;
    private EapTlsConfig tlsConfig;
    private Duration cacheTtl = Duration.ofSeconds(5);

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
    /** Rewrites each answer of the peer before it is sent (a peer claiming another method version). */
    private java.util.function.UnaryOperator<byte[]> tamper = a -> a;
    /** {@code auth.eap.peap.client.certificate} for the handlers made next. */
    private boolean peapCertificate;

    private int converse(StoreAccessHandler h, String identity, EapTlsClient client, int type) throws Exception {
        int code = handle(h, StoreAccessHandlerTest.identity(1, identity), null);
        int rounds = 0;
        while (code == AccessHandler.CHALLENGE && rounds++ < 300) {
            EapPacket request = EapPacket.from(reply());
            assertThat(request.type()).isEqualTo(type);
            byte[] answer = tamper.apply(client.answer(request.data()));
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

    // ---- identity and certificate, revocation, reload (ADR 0033) --------------------------------

    private StoreAccessHandler tlsWith(TlsCredentials credentials, CertificateIdentity.Check identity) {
        tlsConfig = new EapTlsConfig(credentials, List.of("TLSv1.2", "TLSv1.3"), 1024, 65_536, false, identity);
        return handler(1024, false, 65_536);
    }

    private int tls(StoreAccessHandler h, String identity, TestPki.Issued certificate) throws Exception {
        return converse(h, identity, new EapTlsClient(TestPki.clientContext(certificate, pki.ca), "TLSv1.3", 1024));
    }

    @Test
    void theIdentityMustNameTheCertificate() throws Exception {
        StoreAccessHandler h = handler(1024, false, 65_536);
        TestPki.Issued laptop = pki.client("laptop-1");
        assertThat(tls(h, "laptop-1", laptop)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(tls(h, "laptop-2", laptop))
                .as("another device's identity with this certificate")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(tls(h, "anonymous", laptop)).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void theCertificateNamesTheUserOrAnyCertificateWillDo() throws Exception {
        store.user("alice@corp.test", List.of(), List.of(new AttributeItem("Filter-Id", "=", "staff")));
        TestPki.Issued alice = pki.client("Alice Smith", TestPki.upn("alice@corp.test"));
        StoreAccessHandler byCertificate = tlsWith(
                EapTlsConfig.context(pki.serverPem, pki.serverKey, pki.caPem), CertificateIdentity.Check.CERTIFICATE);
        assertThat(tls(byCertificate, "anonymous@corp.test", alice)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(reply().findAttribute(11))
                .as("alice's reply items, found by the UPN")
                .isPositive();

        StoreAccessHandler any =
                tlsWith(EapTlsConfig.context(pki.serverPem, pki.serverKey, pki.caPem), CertificateIdentity.Check.ANY);
        assertThat(tls(any, "whoever", pki.client("laptop-9"))).isEqualTo(AccessHandler.ACCEPT);
    }

    private TlsCredentials revocation(
            List<Path> crls, TlsCredentials.Revocation revocation, java.net.URI ocsp, boolean softFail) {
        return new TlsCredentials(
                pki.serverPem, pki.serverKey, pki.caPem, crls, revocation, ocsp, softFail, Duration.ZERO);
    }

    @Test
    void revokedCertificatesFailAgainstACrl() throws Exception {
        TestPki.Issued good = pki.client("good-1");
        TestPki.Issued revoked = pki.client("stolen-1");
        Path crl = pki.crl(dir.resolve("corp.crl"), revoked);
        StoreAccessHandler h = tlsWith(
                revocation(List.of(crl), TlsCredentials.Revocation.CRL, null, false), CertificateIdentity.Check.MATCH);
        assertThat(tls(h, "good-1", good)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(tls(h, "stolen-1", revoked)).isEqualTo(AccessHandler.REJECT);

        Path foreign = other.crl(dir.resolve("other.crl"));
        StoreAccessHandler noCrl = tlsWith(
                revocation(List.of(foreign), TlsCredentials.Revocation.CRL, null, false),
                CertificateIdentity.Check.MATCH);
        assertThat(tls(noCrl, "good-1", good))
                .as("no CRL of its issuer: unknown status fails")
                .isEqualTo(AccessHandler.REJECT);
        StoreAccessHandler soft = tlsWith(
                revocation(List.of(foreign), TlsCredentials.Revocation.CRL, null, true),
                CertificateIdentity.Check.MATCH);
        assertThat(tls(soft, "good-1", good))
                .as("soft fail: unknown status passes")
                .isEqualTo(AccessHandler.ACCEPT);
    }

    @Test
    void revokedCertificatesFailAgainstAnOcspResponder() throws Exception {
        TestPki.Issued good = pki.client("good-2");
        TestPki.Issued revoked = pki.client("stolen-2");
        com.sun.net.httpserver.HttpServer responder =
                pki.ocspResponder(java.util.Set.of(revoked.certificate().getSerialNumber()));
        try {
            java.net.URI url = java.net.URI.create(
                    "http://127.0.0.1:" + responder.getAddress().getPort() + "/");
            StoreAccessHandler h = tlsWith(
                    revocation(List.of(), TlsCredentials.Revocation.OCSP, url, false), CertificateIdentity.Check.MATCH);
            int before = pki.ocspRequests.get();
            assertThat(tls(h, "good-2", good)).isEqualTo(AccessHandler.ACCEPT);
            assertThat(pki.ocspRequests.get()).as("the responder was asked").isGreaterThan(before);
            assertThat(tls(h, "stolen-2", revoked)).isEqualTo(AccessHandler.REJECT);
        } finally {
            responder.stop(0);
        }
        java.net.URI down = java.net.URI.create("http://127.0.0.1:9/");
        StoreAccessHandler hard = tlsWith(
                revocation(List.of(), TlsCredentials.Revocation.OCSP, down, false), CertificateIdentity.Check.MATCH);
        assertThat(tls(hard, "good-2", good)).as("responder unreachable").isEqualTo(AccessHandler.REJECT);
        StoreAccessHandler soft = tlsWith(
                revocation(List.of(), TlsCredentials.Revocation.OCSP, down, true), CertificateIdentity.Check.MATCH);
        assertThat(tls(soft, "good-2", good))
                .as("responder unreachable, soft fail")
                .isEqualTo(AccessHandler.ACCEPT);
    }

    @Test
    void certificatesAreReloadedWhenTheirFilesChange() throws Exception {
        Path chain = dir.resolve("reload.pem");
        Path key = dir.resolve("reload.key");
        java.nio.file.Files.copy(pki.serverPem, chain, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        java.nio.file.Files.copy(pki.serverKey, key, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        TlsCredentials credentials = new TlsCredentials(
                chain, key, pki.caPem, List.of(), TlsCredentials.Revocation.NONE, null, false, Duration.ofMillis(1));
        javax.net.ssl.SSLContext first = credentials.current();

        TestPki renewed = new TestPki(dir, "renewed");
        java.nio.file.Files.copy(renewed.serverPem, chain, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        touch(chain, 10_000);
        Thread.sleep(5);
        assertThat(credentials.current())
                .as("a new certificate without its key")
                .isSameAs(first);
        assertThat(credentials.reloadFailures()).isEqualTo(1);

        java.nio.file.Files.copy(renewed.serverKey, key, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        touch(key, 20_000);
        Thread.sleep(5);
        javax.net.ssl.SSLContext second = credentials.current();
        assertThat(second).isNotSameAs(first);
        assertThat(credentials.reloads()).isEqualTo(1);

        StoreAccessHandler h = tlsWith(credentials, CertificateIdentity.Check.MATCH);
        EapTlsClient trustsRenewed =
                new EapTlsClient(TestPki.clientContext(pki.client("laptop-3"), renewed.ca), "TLSv1.3", 1024);
        assertThat(converse(h, "laptop-3", trustsRenewed))
                .as("the renewed server certificate is served")
                .isEqualTo(AccessHandler.ACCEPT);
        var metrics = new io.radiusward.common.management.PrometheusWriter();
        h.writeMetrics(metrics, "1");
        assertThat(metrics.finish())
                .contains("radiusward_gateway_eap_tls_reloads_total{gateway=\"1\",result=\"loaded\"} 1")
                .contains("radiusward_gateway_eap_tls_reloads_total{gateway=\"1\",result=\"failed\"} 1");
    }

    private static void touch(Path file, long plusMillis) throws Exception {
        java.nio.file.Files.setLastModifiedTime(
                file, java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis() + plusMillis));
    }

    @Test
    void mismatchedKeysAndMissingRevocationDataAreConfigErrors() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new TlsCredentials(
                        pki.serverPem,
                        other.serverKey,
                        pki.caPem,
                        List.of(),
                        TlsCredentials.Revocation.NONE,
                        null,
                        false,
                        Duration.ZERO))
                .hasMessageContaining("is not the key of the certificate");
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> revocation(List.of(), TlsCredentials.Revocation.CRL, null, false))
                .hasMessageContaining("auth.eap.tls.crl");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new TlsCredentials(
                        pki.serverPem,
                        pki.serverKey,
                        null,
                        List.of(),
                        TlsCredentials.Revocation.OCSP,
                        null,
                        false,
                        Duration.ZERO))
                .hasMessageContaining("auth.eap.tls.ca");
    }

    @Test
    void configurationKeys() {
        Map<String, String> base = Map.of(
                "auth.eap.methods", "tls, peap",
                "auth.eap.tls.certificate", pki.serverPem.toString(),
                "auth.eap.tls.key", pki.serverKey.toString(),
                "auth.eap.tls.ca", pki.caPem.toString());
        EapConfig defaults = EapConfig.from(io.radiusward.common.config.Config.of(base));
        assertThat(defaults.tls().identity()).isEqualTo(CertificateIdentity.Check.MATCH);
        assertThat(defaults.peapBinding()).isEqualTo(Peap.Binding.OPTIONAL);
        assertThat(defaults.peapClientCertificate()).as("as other servers: off").isFalse();

        Map<String, String> custom = new java.util.HashMap<>(base);
        custom.put("auth.eap.tls.identity", "certificate");
        custom.put("auth.eap.peap.crypto.binding", "Required");
        custom.put("auth.eap.tls.revocation", "ocsp");
        custom.put("auth.eap.tls.ocsp.url", "http://127.0.0.1:9/");
        custom.put("auth.eap.tls.reload", "0s");
        custom.put("auth.eap.peap.client.certificate", "true");
        EapConfig set = EapConfig.from(io.radiusward.common.config.Config.of(custom));
        assertThat(set.peapClientCertificate()).isTrue();
        assertThat(set.tls().identity()).isEqualTo(CertificateIdentity.Check.CERTIFICATE);
        assertThat(set.peapBinding()).isEqualTo(Peap.Binding.REQUIRED);
        assertThat(set.outerOptional(EapTls.TYPE)).isTrue();

        for (String[] wrong : new String[][] {
            {"auth.eap.tls.identity", "cn"},
            {"auth.eap.peap.crypto.binding", "maybe"},
            {"auth.eap.tls.revocation", "both"}
        }) {
            Map<String, String> bad = new java.util.HashMap<>(base);
            bad.put(wrong[0], wrong[1]);
            org.assertj.core.api.Assertions.assertThatThrownBy(
                            () -> EapConfig.from(io.radiusward.common.config.Config.of(bad)))
                    .hasMessageContaining(wrong[0]);
        }
        Map<String, String> noCa = new java.util.HashMap<>(base);
        noCa.remove("auth.eap.tls.ca");
        noCa.put("auth.eap.methods", "peap");
        noCa.put("auth.eap.peap.client.certificate", "true");
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> EapConfig.from(io.radiusward.common.config.Config.of(noCa)))
                .hasMessageContaining("auth.eap.peap.client.certificate: needs auth.eap.tls.ca");
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
    void aPeerClaimingAHigherVersionFails() throws Exception {
        store.user(
                        "alice",
                        List.of(new AttributeItem("NT-Password", ":=", HexFormatHolder.hex(MsChap.ntHash("Alice-Pw")))),
                        List.of())
                .user("carol", List.of(new AttributeItem("Cleartext-Password", ":=", "Carol-Pw")), List.of());
        tamper = a -> {
            byte[] b = a.clone();
            b[0] |= 1; // PEAPv1, TTLSv1: above the version 0 offered
            return b;
        };
        assertThat(converse(peap(), "anonymous", peapClient("TLSv1.2", new PeapPeer("alice", "Alice-Pw")), Peap.TYPE))
                .as("PEAPv1")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(converse(
                        ttls(Map.of(), Map.of(), Map.of()),
                        "anonymous",
                        ttlsClient("TLSv1.2", new TtlsPeer("carol", "Carol-Pw", false, false)),
                        Ttls.TYPE))
                .as("TTLSv1")
                .isEqualTo(AccessHandler.REJECT);
        tamper = a -> a;
        assertThat(converse(peap(), "anonymous", peapClient("TLSv1.2", new PeapPeer("alice", "Alice-Pw")), Peap.TYPE))
                .as("PEAPv0")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(converse(
                        ttls(Map.of(), Map.of(), Map.of()),
                        "anonymous",
                        ttlsClient("TLSv1.2", new TtlsPeer("carol", "Carol-Pw", false, false)),
                        Ttls.TYPE))
                .as("TTLSv0")
                .isEqualTo(AccessHandler.ACCEPT);
    }

    @Test
    void eapTlsIgnoresTheReservedBits() throws Exception {
        tamper = a -> {
            byte[] b = a.clone();
            b[0] |= 0x07; // reserved in EAP-TLS (RFC 5216 §3.1): ignored on receipt
            return b;
        };
        assertThat(converse(
                        handler(1024, false, 65_536),
                        "nas-user",
                        new EapTlsClient(TestPki.clientContext(pki.client("nas-user"), pki.ca), "TLSv1.3", 1024)))
                .isEqualTo(AccessHandler.ACCEPT);
    }

    @Test
    void peapMayRequireAClientCertificate() throws Exception {
        store.user(
                "alice",
                List.of(new AttributeItem("NT-Password", ":=", HexFormatHolder.hex(MsChap.ntHash("Alice-Pw")))),
                List.of());
        peapCertificate = true;
        StoreAccessHandler h = peap();
        assertThat(converse(h, "anonymous", peapClient("TLSv1.3", new PeapPeer("alice", "Alice-Pw")), Peap.TYPE))
                .as("no client certificate")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(converse(
                        h,
                        "anonymous",
                        new EapTlsClient(
                                TestPki.clientContext(other.client("laptop-7"), pki.ca),
                                "TLSv1.3",
                                1024,
                                new PeapPeer("alice", "Alice-Pw")),
                        Peap.TYPE))
                .as("a certificate of another CA")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(converse(
                        h,
                        "anonymous",
                        new EapTlsClient(
                                TestPki.clientContext(pki.client("laptop-7"), pki.ca),
                                "TLSv1.3",
                                1024,
                                new PeapPeer("alice", "Alice-Pw")),
                        Peap.TYPE))
                .as("a certificate of auth.eap.tls.ca, then the inner method as usual")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(converse(
                        h,
                        "anonymous",
                        new EapTlsClient(
                                TestPki.clientContext(pki.client("laptop-7"), pki.ca),
                                "TLSv1.3",
                                1024,
                                new PeapPeer("alice", "wrong")),
                        Peap.TYPE))
                .as("the certificate does not replace the password")
                .isEqualTo(AccessHandler.REJECT);
        peapCertificate = false;
    }

    @Test
    void peapCryptoBindingRequiredOrBroken() throws Exception {
        store.user(
                "alice",
                List.of(new AttributeItem("NT-Password", ":=", HexFormatHolder.hex(MsChap.ntHash("Alice-Pw")))),
                List.of());
        binding = Peap.Binding.REQUIRED;
        assertThat(converse(peap(), "anonymous", peapClient("TLSv1.3", new PeapPeer("alice", "Alice-Pw")), Peap.TYPE))
                .as("required, but the peer does not answer the Crypto-Binding TLV")
                .isEqualTo(AccessHandler.REJECT);
        binding = Peap.Binding.OPTIONAL;
        PeapPeer broken = new PeapPeer("alice", "Alice-Pw");
        broken.echoBinding = true;
        assertThat(converse(peap(), "anonymous", peapClient("TLSv1.2", broken), Peap.TYPE))
                .as("a Crypto-Binding TLV that does not verify fails even when optional")
                .isEqualTo(AccessHandler.REJECT);
        binding = Peap.Binding.OFF;
        PeapPeer plain = new PeapPeer("alice", "Alice-Pw");
        plain.echoBinding = true;
        EapTlsClient client = peapClient("TLSv1.2", plain);
        assertThat(converse(peap(), "anonymous", client, Peap.TYPE))
                .as("off: none sent, the tunnel's keys")
                .isEqualTo(AccessHandler.ACCEPT);
        assertKeys(client, Peap.TYPE);
    }

    @Test
    void resumedTunnelsSkipTheInnerMethodButAreAuthorizedAgain() throws Exception {
        cacheTtl = Duration.ZERO; // the store's change is seen at once, not after auth.cache.ttl
        for (String protocol : new String[] {"TLSv1.2", "TLSv1.3"}) {
            store.user(
                    "alice",
                    List.of(new AttributeItem("NT-Password", ":=", HexFormatHolder.hex(MsChap.ntHash("Alice-Pw")))),
                    List.of(new AttributeItem("Filter-Id", "=", "staff")));
            StoreAccessHandler h = peap();
            javax.net.ssl.SSLContext laptop = TestPki.clientContext(null, pki.ca);
            assertThat(converse(
                            h,
                            "anonymous",
                            new EapTlsClient(laptop, protocol, 1024, new PeapPeer("alice", "Alice-Pw")),
                            Peap.TYPE))
                    .isEqualTo(AccessHandler.ACCEPT);

            PeapPeer forgetful = new PeapPeer("alice", "not-asked");
            EapTlsClient resumed = new EapTlsClient(laptop, protocol, 1024, forgetful);
            assertThat(converse(h, "anonymous", resumed, Peap.TYPE))
                    .as(protocol + ": the resumed session's user, no inner method")
                    .isEqualTo(AccessHandler.ACCEPT);
            assertThat(forgetful.challengeHash).as("no MS-CHAPv2 exchange").isNull();
            assertThat(reply().findAttribute(11)).as("alice's reply items").isPositive();
            assertKeys(resumed, Peap.TYPE);

            store.user("alice", List.of(new AttributeItem("Auth-Type", ":=", "Reject")), List.of());
            assertThat(converse(h, "anonymous", new EapTlsClient(laptop, protocol, 1024, forgetful), Peap.TYPE))
                    .as("disabled since: the resumed session's user is authorized again")
                    .isEqualTo(AccessHandler.REJECT);
        }
    }

    @Test
    void eapTlsResumesAndAFailedSessionDoesNot() throws Exception {
        StoreAccessHandler h = handler(1024, false, 65_536);
        for (String protocol : new String[] {"TLSv1.2", "TLSv1.3"}) {
            javax.net.ssl.SSLContext device = TestPki.clientContext(pki.client("laptop-5"), pki.ca);
            assertThat(converse(h, "laptop-5", new EapTlsClient(device, protocol, 1024)))
                    .isEqualTo(AccessHandler.ACCEPT);
            EapTlsClient again = new EapTlsClient(device, protocol, 1024);
            assertThat(converse(h, "laptop-5", again)).isEqualTo(AccessHandler.ACCEPT);
            assertKeys(again);
        }
        var metrics = new io.radiusward.common.management.PrometheusWriter();
        h.writeMetrics(metrics, "1");
        assertThat(metrics.finish()).contains("radiusward_gateway_eap_tls_resumptions_total{gateway=\"1\"} 2");
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

    // ---- EAP-TTLS (ADR 0030) ------------------------------------------------------------------------

    private StoreAccessHandler ttls(
            Map<String, Boolean> mschap,
            Map<String, io.radiusward.auth.CredentialVerifier> verifiers,
            Map<String, String> storeVerifiers) {
        return handler(1024, false, 65_536, List.of("ttls"), mschap, verifiers, storeVerifiers);
    }

    private EapTlsClient ttlsClient(String protocol, TtlsPeer peer) throws Exception {
        EapTlsClient client = new EapTlsClient(TestPki.clientContext(null, pki.ca), protocol, 1024, peer);
        peer.client = client;
        return client;
    }

    @Test
    void ttlsPapWithStoredPasswords() throws Exception {
        store.user(
                        "carol",
                        List.of(new AttributeItem("Cleartext-Password", ":=", "Carol-Pw")),
                        List.of(new AttributeItem("Filter-Id", "=", "guest")))
                .user(
                        "dave",
                        List.of(new AttributeItem(
                                "Crypt-Password",
                                ":=",
                                ShaCrypt.crypt("Dave-Pw".getBytes(StandardCharsets.UTF_8), "$6$rounds=1000$salt"))),
                        List.of());
        for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
            EapTlsClient client = ttlsClient(protocol, new TtlsPeer("carol", "Carol-Pw", false, false));
            assertThat(converse(ttls(Map.of(), Map.of(), Map.of()), "anonymous", client, Ttls.TYPE))
                    .as(protocol)
                    .isEqualTo(AccessHandler.ACCEPT);
            assertThat(reply().findAttribute(11))
                    .as("the inner user's reply items")
                    .isPositive();
            assertKeys(client, Ttls.TYPE);
        }
        assertThat(converse(
                        ttls(Map.of(), Map.of(), Map.of()),
                        "anonymous",
                        ttlsClient("TLSv1.3", new TtlsPeer("dave", "Dave-Pw", false, false)),
                        Ttls.TYPE))
                .as("a SHA-crypt hash")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(converse(
                        ttls(Map.of(), Map.of(), Map.of()),
                        "anonymous",
                        ttlsClient("TLSv1.2", new TtlsPeer("dave", "wrong", false, false)),
                        Ttls.TYPE))
                .isEqualTo(AccessHandler.REJECT);
        assertThat(EapPacket.from(reply()).code()).isEqualTo(EapPacket.FAILURE);
    }

    @Test
    void ttlsMsChapV2WithTheImplicitChallenge() throws Exception {
        store.user(
                "erin",
                List.of(new AttributeItem("NT-Password", ":=", HexFormatHolder.hex(MsChap.ntHash("Erin-Pw")))),
                List.of());
        TtlsPeer peer = new TtlsPeer("erin", "Erin-Pw", true, false);
        EapTlsClient client = ttlsClient("TLSv1.3", peer);
        assertThat(converse(ttls(Map.of(), Map.of(), Map.of()), "anonymous", client, Ttls.TYPE))
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(peer.serverProved).as("MS-CHAP2-Success with the right S=").isTrue();
        assertKeys(client, Ttls.TYPE);

        TtlsPeer relayed = new TtlsPeer("erin", "Erin-Pw", true, true);
        assertThat(converse(ttls(Map.of(), Map.of(), Map.of()), "anonymous", ttlsClient("TLSv1.2", relayed), Ttls.TYPE))
                .as("a challenge not derived from this tunnel")
                .isEqualTo(AccessHandler.REJECT);
        TtlsPeer wrong = new TtlsPeer("erin", "nope", true, false);
        assertThat(converse(ttls(Map.of(), Map.of(), Map.of()), "anonymous", ttlsClient("TLSv1.2", wrong), Ttls.TYPE))
                .isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void ttlsPapThroughAVerifierAndItsOutage() throws Exception {
        StoreAccessHandlerTest.FakeVerifier ad = new StoreAccessHandlerTest.FakeVerifier();
        store.user("User", List.of(), List.of());
        StoreAccessHandler h = ttls(Map.of(), Map.of("ad", ad), Map.of("main", "ad"));
        assertThat(converse(
                        h,
                        "anonymous",
                        ttlsClient("TLSv1.3", new TtlsPeer("User", "clientPass", false, false)),
                        Ttls.TYPE))
                .as("PAP against a directory, e.g. LDAP bind or Netlogon")
                .isEqualTo(AccessHandler.ACCEPT);
        ad.down = true;
        assertThat(converse(
                        h,
                        "anonymous",
                        ttlsClient("TLSv1.2", new TtlsPeer("User", "clientPass", false, false)),
                        Ttls.TYPE))
                .isEqualTo(AccessHandler.DROP);
        ad.down = false;
        assertThat(handle(h, lastResponse, lastState))
                .as("the retransmission repeats the check")
                .isEqualTo(AccessHandler.ACCEPT);
    }

    // ---- PEAP with inner EAP-GTC and EAP-TLS (ADR 0031) -----------------------------------------------

    private StoreAccessHandler peapWith(
            List<Integer> inner,
            Map<String, io.radiusward.auth.CredentialVerifier> verifiers,
            Map<String, String> storeVerifiers) {
        return handler(1024, false, 65_536, List.of("peap"), Map.of(), verifiers, storeVerifiers, inner);
    }

    @Test
    void peapGtcChosenByNakAndCheckedLikePap() throws Exception {
        store.user(
                "frank",
                List.of(new AttributeItem(
                        "Crypt-Password",
                        ":=",
                        ShaCrypt.crypt("Frank-Pw".getBytes(StandardCharsets.UTF_8), "$6$rounds=1000$s"))),
                List.of(new AttributeItem("Filter-Id", "=", "otp")));
        StoreAccessHandler h = peapWith(List.of(Peap.MS_CHAP_V2, Peap.GTC), Map.of(), Map.of());
        PeapPeer peer = new PeapPeer("frank", "Frank-Pw", Peap.GTC, null);
        EapTlsClient client = peapClient("TLSv1.3", peer);
        assertThat(converse(h, "anonymous", client, Peap.TYPE)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(reply().findAttribute(11)).isPositive();
        assertKeys(client, Peap.TYPE);
        assertThat(converse(
                        h,
                        "anonymous",
                        peapClient("TLSv1.2", new PeapPeer("frank", "nope", Peap.GTC, null)),
                        Peap.TYPE))
                .isEqualTo(AccessHandler.REJECT);
        assertThat(converse(
                        peapWith(List.of(Peap.MS_CHAP_V2), Map.of(), Map.of()),
                        "anonymous",
                        peapClient("TLSv1.3", new PeapPeer("frank", "Frank-Pw", Peap.GTC, null)),
                        Peap.TYPE))
                .as("GTC is not offered: the Nak finds nothing")
                .isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void peapGtcAgainstAPapOnlyDirectory() throws Exception {
        StoreAccessHandlerTest.FakeVerifier ldap = new StoreAccessHandlerTest.FakeVerifier();
        store.user("User", List.of(), List.of());
        StoreAccessHandler h = peapWith(List.of(Peap.GTC), Map.of("ldap", ldap), Map.of("main", "ldap"));
        assertThat(converse(
                        h,
                        "anonymous",
                        peapClient("TLSv1.3", new PeapPeer("User", "clientPass", Peap.GTC, null)),
                        Peap.TYPE))
                .as("no NT hash needed: the directory checks the password")
                .isEqualTo(AccessHandler.ACCEPT);
    }

    @Test
    void peapWithAClientCertificateInside() throws Exception {
        StoreAccessHandler h = peapWith(List.of(EapTls.TYPE), Map.of(), Map.of());
        EapTlsClient inner = new EapTlsClient(TestPki.clientContext(pki.client("laptop-9"), pki.ca), "TLSv1.2", 1024);
        EapTlsClient outer = peapClient("TLSv1.3", new PeapPeer("laptop-9", null, EapTls.TYPE, inner));
        assertThat(converse(h, "anonymous", outer, Peap.TYPE))
                .as("a valid inner certificate, the user in no store")
                .isEqualTo(AccessHandler.ACCEPT);
        assertKeys(outer, Peap.TYPE);

        EapTlsClient stranger = new EapTlsClient(TestPki.clientContext(other.client("x"), pki.ca), "TLSv1.3", 1024);
        assertThat(converse(
                        h,
                        "anonymous",
                        peapClient("TLSv1.2", new PeapPeer("x", null, EapTls.TYPE, stranger)),
                        Peap.TYPE))
                .isEqualTo(AccessHandler.REJECT);
    }
}
