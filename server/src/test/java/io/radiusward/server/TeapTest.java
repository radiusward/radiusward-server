/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.eap.EapPacket;
import io.radiusward.server.EapMethod.Credentials;
import io.radiusward.server.EapMethod.Step;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * TEAP's TLV parsing, configuration, and conversations with a JDK TLS client as the peer ({@link TeapPeer}; ADR 0041);
 * with real peers: {@code EapolTestIT}, {@code ExternalEapComparisonIT}.
 */
class TeapTest {

    @TempDir
    static Path dir;

    static TestPki pki;

    @BeforeAll
    static void certificates() throws Exception {
        pki = new TestPki(dir, "teap");
    }

    private final InnerEapTest.Checks checks = new InnerEapTest.Checks();
    private Credentials credentials = new Credentials(List.of(), false, checks);
    /** Rewrites each message of the peer's TLS client (its EAP-TEAP type data) before the server gets it. */
    private UnaryOperator<byte[]> tamper = a -> a;

    private EapTlsClient client;
    private byte[] lastAnswer;

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    @Test
    void tlvsAreParsed() {
        byte[] eap = new EapPacket(EapPacket.CODE_RESPONSE, 7, EapPacket.TYPE_IDENTITY, new byte[] {'a'}).encode();
        Teap.Tlvs t = Teap.Tlvs.parse(concat(
                Teap.tlv(Teap.MANDATORY | Teap.TLV_RESULT, new byte[] {0, 1}),
                Teap.tlv(Teap.MANDATORY | Teap.TLV_INTERMEDIATE_RESULT, new byte[] {0, 2}),
                Teap.tlv(Teap.MANDATORY | Teap.TLV_EAP_PAYLOAD, concat(eap, new byte[] {0, 2, 0, 2, 0, 1})),
                Teap.tlv(Teap.TLV_NAK, new byte[6]),
                Teap.tlv(77, new byte[3]))); // an unknown optional TLV is skipped
        assertThat(t.result).isEqualTo(Teap.SUCCESS);
        assertThat(t.intermediate).isEqualTo(Teap.FAILURE);
        assertThat(t.eapPayload).as("the EAP packet without the TLVs after it").isEqualTo(eap);
        assertThat(t.nak).isTrue();
        assertThat(Teap.Tlvs.parse(Teap.tlv(Teap.MANDATORY | 77, new byte[1])))
                .as("an unknown mandatory TLV")
                .isNull();
        assertThat(Teap.Tlvs.parse(new byte[] {0, 3, 0, 9, 0})).as("truncated").isNull();
        assertThat(Teap.Tlvs.parse(new byte[] {0, 3}))
                .as("no room for a header")
                .isNull();
        assertThat(Teap.Tlvs.parse(Teap.tlv(Teap.TLV_RESULT, new byte[] {1})).result)
                .as("a malformed status is a failure")
                .isEqualTo(Teap.FAILURE);
        assertThat(Teap.Tlvs.parse(Teap.tlv(Teap.TLV_EAP_PAYLOAD, new byte[] {2, 7, 0})).eapPayload)
                .as("too short for an EAP header: left as it is, for the EAP parser to refuse")
                .containsExactly(2, 7, 0);
        assertThat(Teap.Tlvs.parse(Teap.tlv(Teap.TLV_EAP_PAYLOAD, new byte[] {2, 7, 0, 9, 1})).eapPayload)
                .as("an EAP length beyond the TLV: left as it is")
                .containsExactly(2, 7, 0, 9, 1);
    }

    @Test
    void configuration() throws Exception {
        Map<String, String> base = new HashMap<>(Map.of(
                "auth.eap.methods", "teap",
                "auth.eap.tls.certificate", pki.serverPem.toString(),
                "auth.eap.tls.key", pki.serverKey.toString(),
                "auth.eap.tls.ca", pki.caPem.toString()));
        EapConfig defaults = EapConfig.from(Config.of(base));
        assertThat(defaults.teapInner()).containsExactly(InnerEap.MS_CHAP_V2, InnerEap.GTC, InnerEap.MD5);
        assertThat(defaults.teapIdentity()).isEmpty();
        assertThat(new String(defaults.teapAuthorityId())).isEqualTo("radiusward");
        assertThat(defaults.outerOptional(Teap.TYPE)).isTrue();
        assertThat(defaults.create(Teap.TYPE, "anonymous")).isInstanceOf(Teap.class);

        Map<String, String> set = new HashMap<>(base);
        set.put("auth.eap.teap.inner", "tls, basic");
        set.put("auth.eap.teap.identity", "machine, user");
        set.put("auth.eap.teap.authority.id", "aaa.corp.example");
        EapConfig custom = EapConfig.from(Config.of(set));
        assertThat(custom.teapInner()).containsExactly(InnerEap.TLS, Teap.BASIC);
        assertThat(custom.teapIdentity()).containsExactly(Teap.IDENTITY_MACHINE, Teap.IDENTITY_USER);

        for (String[] wrong : new String[][] {
            {"auth.eap.teap.inner", "pap", "auth.eap.teap.inner"},
            {"auth.eap.teap.identity", "device", "auth.eap.teap.identity"},
            {"auth.eap.teap.identity", "user, user", "auth.eap.teap.identity"},
            {"auth.eap.teap.authority.id", "x".repeat(256), "auth.eap.teap.authority.id"}
        }) {
            Map<String, String> bad = new HashMap<>(base);
            bad.put(wrong[0], wrong[1]);
            assertThatThrownBy(() -> EapConfig.from(Config.of(bad))).hasMessageContaining(wrong[2]);
        }
        Map<String, String> noCa = new HashMap<>(base);
        noCa.remove("auth.eap.tls.ca");
        noCa.put("auth.eap.teap.inner", "tls");
        assertThatThrownBy(() -> EapConfig.from(Config.of(noCa))).hasMessageContaining("tls needs auth.eap.tls.ca");
        assertThat(List.of(EapConfig.type("teap"))).containsExactly(Teap.TYPE);
    }

    // ---- conversations ------------------------------------------------------------------------------

    private static EapTlsConfig tls() {
        return new EapTlsConfig(
                EapTlsConfig.context(pki.serverPem, pki.serverKey, pki.caPem),
                List.of("TLSv1.2", "TLSv1.3"),
                1024,
                65_536,
                false);
    }

    private static Teap teap(List<Integer> inner) {
        return new Teap(tls(), inner, EapConfig.DEFAULT_AUTHORITY_ID);
    }

    private static Teap teap(List<Integer> inner, List<Integer> identityTypes) {
        return new Teap(tls(), inner, EapConfig.DEFAULT_AUTHORITY_ID, identityTypes);
    }

    /** A whole conversation up to the server's last step: success, failure, or a wait for a retransmission. */
    private Step converse(Teap teap, String protocol, TeapPeer peer) throws Exception {
        client = new EapTlsClient(TestPki.clientContext(null, pki.ca), protocol, 1024, peer);
        peer.client = client;
        return proceed(teap, teap.start(1, credentials));
    }

    private Step proceed(Teap teap, Step step) throws Exception {
        for (int round = 0; round < 300 && !step.done(); round++) {
            lastAnswer = tamper.apply(client.answer(step.request()));
            step = teap.process(round + 2, lastAnswer, credentials);
        }
        return step;
    }

    private static void assertSucceeded(Step step, TeapPeer peer) {
        assertThat(step.success()).isTrue();
        assertThat(peer.serverBindingValid).as("the server's Compound MAC").isTrue();
        assertThat(step.msk())
                .as("the MSK from the last S-IMCK, as the peer derives it")
                .isEqualTo(peer.msk);
    }

    private static void assertFailed(Step step) {
        assertThat(step.success()).isFalse();
        assertThat(step.done()).isTrue();
        assertThat(step.unavailable()).isFalse();
    }

    private static TeapPeer alice() {
        return new TeapPeer("alice", InnerEapTest.PASSWORD);
    }

    /** The TLVs of a plaintext answer, each replaced by what {@code change} makes of its type and value. */
    private static byte[] mapTlvs(byte[] tlvs, java.util.function.BiFunction<Integer, byte[], byte[]> change) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int at = 0; at < tlvs.length; ) {
            int raw = (tlvs[at] & 0xFF) << 8 | (tlvs[at + 1] & 0xFF);
            int length = (tlvs[at + 2] & 0xFF) << 8 | (tlvs[at + 3] & 0xFF);
            byte[] whole = java.util.Arrays.copyOfRange(tlvs, at, at + 4 + length);
            byte[] changed = change.apply(raw & 0x3FFF, whole);
            out.writeBytes(changed);
            at += 4 + length;
        }
        return out.toByteArray();
    }

    /** An answer without the TLVs of {@code type}. */
    private static UnaryOperator<byte[]> without(int type) {
        return a -> mapTlvs(a, (t, whole) -> t == type ? new byte[0] : whole);
    }

    @Test
    void basicPasswordAuthOverBothTlsVersions() throws Exception {
        for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
            Teap teap = teap(List.of(Teap.BASIC));
            TeapPeer peer = alice();
            Step step = converse(teap, protocol, peer);
            assertSucceeded(step, peer);
            assertThat(peer.result)
                    .as(protocol + ": the Result came with the binding")
                    .isEqualTo(Teap.SUCCESS);
            assertThat(teap.innerIdentity()).isEqualTo("alice");
            assertThat(teap.type()).isEqualTo(Teap.TYPE);
        }
        TeapPeer wrong = new TeapPeer("alice", "nope");
        assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.3", wrong));
        assertThat(wrong.result).as("a failed Result first").isEqualTo(Teap.FAILURE);
        assertThat(wrong.bindings).isZero();
    }

    @Test
    void malformedBasicPasswordAuthResponsesFail() throws Exception {
        byte[][] malformed = {
            {}, // no Userlen
            {5, 'a', 'l'}, // a Userlen beyond the value
            {1, 'a', 3, 'x'}, // a Passlen that does not end the value
            {1, 'a', 1, 'x', 'y'}
        };
        for (byte[] value : malformed) {
            TeapPeer peer = alice();
            peer.basicAuthValue = value;
            assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.3", peer));
            assertThat(peer.result).as(java.util.Arrays.toString(value)).isEqualTo(Teap.FAILURE);
        }
        assertThat(checks.calls).as("no password checked").isZero();

        credentials = new Credentials(List.of(), false); // no inner checks: nothing can tell
        TeapPeer peer = alice();
        assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.2", peer));
        assertThat(peer.result).isEqualTo(Teap.FAILURE);
    }

    @Test
    void aMissingBasicPasswordAuthResponseFails() throws Exception {
        TeapPeer peer = alice();
        peer.rewrite = a -> Teap.tlv(Teap.TLV_IDENTITY_TYPE, new byte[] {0, 1});
        assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.3", peer));
        assertThat(peer.basicAnswers).isEqualTo(1);
    }

    @Test
    void aNakToBasicPasswordAuthFallsBackToTheEapMethods() throws Exception {
        Teap teap = teap(List.of(Teap.BASIC, InnerEap.MS_CHAP_V2, InnerEap.GTC));
        TeapPeer peer = alice();
        peer.nakBasic = true;
        Step step = converse(teap, "TLSv1.3", peer);
        assertSucceeded(step, peer);
        assertThat(peer.basicAnswers).isEqualTo(1);
        assertThat(teap.innerIdentity()).as("from the inner EAP-GTC").isEqualTo("alice");

        TeapPeer only = alice();
        only.nakBasic = true;
        assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.2", only));
        assertThat(only.bindings).as("no EAP method to fall back to").isZero();
    }

    @Test
    void innerEapGtcChosenByNak() throws Exception {
        for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
            Teap teap = teap(EapConfig.DEFAULT_TEAP_INNER);
            TeapPeer peer = alice();
            assertSucceeded(converse(teap, protocol, peer), peer);
            assertThat(teap.innerIdentity()).isEqualTo("alice");
        }
        TeapPeer wrong = new TeapPeer("alice", "nope");
        assertFailed(converse(teap(EapConfig.DEFAULT_TEAP_INNER), "TLSv1.3", wrong));
        assertThat(wrong.result).isEqualTo(Teap.FAILURE);
    }

    @Test
    void innerEapNeedsItsPayloadAndInnerChecks() throws Exception {
        TeapPeer noPayload = alice();
        noPayload.rewrite = a -> Teap.tlv(Teap.TLV_IDENTITY_TYPE, new byte[] {0, 1}); // no EAP-Payload
        assertFailed(converse(teap(EapConfig.DEFAULT_TEAP_INNER), "TLSv1.3", noPayload));

        credentials = new Credentials(List.of(), false);
        TeapPeer noChecks = alice();
        assertFailed(converse(teap(EapConfig.DEFAULT_TEAP_INNER), "TLSv1.2", noChecks));
        assertThat(noChecks.bindings).isZero();
    }

    @Test
    void innerEapWaitsForTheRetransmissionWhileTheStoreIsDown() throws Exception {
        Teap teap = teap(EapConfig.DEFAULT_TEAP_INNER);
        TeapPeer peer = alice();
        checks.down = true;
        Step step = converse(teap, "TLSv1.3", peer);
        assertThat(step.unavailable())
                .as("the GTC check cannot be made: no answer")
                .isTrue();
        assertThat(teap.process(9, lastAnswer, credentials).unavailable())
                .as("still down: the retransmission waits too")
                .isTrue();
        assertThat(checks.calls).isEqualTo(2);
        checks.down = false;
        step = teap.process(10, lastAnswer, credentials);
        assertThat(step.done())
                .as("the check made again goes on to the binding")
                .isFalse();
        assertSucceeded(proceed(teap, step), peer);
        assertThat(peer.bindings).isEqualTo(1);

        Teap other = teap(EapConfig.DEFAULT_TEAP_INNER);
        checks.down = true;
        assertThat(converse(other, "TLSv1.2", alice()).unavailable()).isTrue();
        byte[] changed = lastAnswer.clone();
        changed[changed.length - 1] ^= 1;
        assertFailed(other.process(9, changed, credentials));
    }

    @Test
    void basicPasswordAuthWaitsForTheRetransmissionWhileTheStoreIsDown() throws Exception {
        Teap teap = teap(List.of(Teap.BASIC));
        TeapPeer peer = alice();
        checks.down = true;
        assertThat(converse(teap, "TLSv1.2", peer).unavailable()).isTrue();
        assertThat(peer.bindings).isZero();
        checks.down = false;
        Step step = teap.process(9, lastAnswer, credentials);
        assertThat(step.done()).isFalse();
        assertSucceeded(proceed(teap, step), peer);
    }

    @Test
    void thePeerEndingTheConversationOrBreakingTheProtocolFails() throws Exception {
        TeapPeer failing = alice();
        failing.rewrite = a -> Teap.tlv(Teap.MANDATORY | Teap.TLV_RESULT, new byte[] {0, Teap.FAILURE});
        assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.3", failing));
        assertThat(checks.calls).as("a failed Result of the peer").isZero();

        TeapPeer unknown = alice();
        unknown.rewrite = a -> Teap.tlv(Teap.MANDATORY | 77, new byte[2]);
        assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.3", unknown));
        assertThat(unknown.result)
                .as("an unknown mandatory TLV ends it at once")
                .isZero();

        TeapPeer ignoring = new TeapPeer("alice", "nope");
        ignoring.failureAnswer = Teap.tlv(Teap.MANDATORY | Teap.TLV_INTERMEDIATE_RESULT, new byte[] {0, Teap.SUCCESS});
        assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.2", ignoring));
        assertThat(ignoring.result)
                .as("a peer ignoring the failed Result still fails")
                .isEqualTo(Teap.FAILURE);

        TeapPeer silent = alice();
        silent.silent = true;
        assertFailed(converse(teap(List.of(Teap.BASIC)), "TLSv1.3", silent));
        assertThat(silent.basicAnswers)
                .as("an acknowledgement where TLVs are due")
                .isZero();
    }

    @Test
    void theCryptoBindingResponseIsChecked() throws Exception {
        Map<String, Consumer<TeapPeer>> broken = new java.util.LinkedHashMap<>();
        broken.put("a version other than 1", p -> p.bindingTamper = b -> b[5] = 2);
        broken.put("a received version other than 1", p -> p.bindingTamper = b -> b[6] = 2);
        broken.put("a request Sub-Type", p -> p.bindingTamper = b -> b[7] = (byte) (2 << 4));
        broken.put("an EMSK Compound MAC only", p -> p.bindingTamper = b -> b[7] = (byte) ((1 << 4) | 1));
        broken.put("another nonce", p -> p.bindingTamper = b -> b[8] ^= 1);
        broken.put("the nonce not answered", p -> p.bindingTamper = b -> b[8 + 31] &= (byte) 0xFE);
        broken.put("a wrong Compound MAC", p -> p.wrongMac = true);
        broken.put("no binding", p -> p.rewrite = without(Teap.TLV_CRYPTO_BINDING));
        broken.put("no Result with the last binding", p -> p.rewrite = without(Teap.TLV_RESULT));
        broken.put(
                "a failed Intermediate-Result",
                p -> p.rewrite = a -> mapTlvs(
                        a,
                        (t, whole) -> t == Teap.TLV_INTERMEDIATE_RESULT
                                ? Teap.tlv(Teap.MANDATORY | t, new byte[] {0, Teap.FAILURE})
                                : whole));
        broken.put(
                "a binding of another length",
                p -> p.rewrite = a -> mapTlvs(
                        a,
                        (t, whole) -> t == Teap.TLV_CRYPTO_BINDING
                                ? Teap.tlv(Teap.MANDATORY | t, java.util.Arrays.copyOfRange(whole, 4, whole.length + 1))
                                : whole));
        for (Map.Entry<String, Consumer<TeapPeer>> e : broken.entrySet()) {
            TeapPeer peer = alice();
            e.getValue().accept(peer);
            Teap teap = teap(List.of(Teap.BASIC));
            assertThat(converse(teap, "TLSv1.3", peer).success()).as(e.getKey()).isFalse();
            assertThat(peer.bindings).as(e.getKey()).isEqualTo(1);
            assertThat(teap.innerIdentity()).as(e.getKey()).isNull();
        }
        TeapPeer both = alice();
        both.bindingTamper = b -> b[7] = (byte) ((3 << 4) | 1);
        assertSucceeded(converse(teap(List.of(Teap.BASIC)), "TLSv1.2", both), both);
    }

    /** Adds the O flag, the Outer TLV Length and {@code tlvs} after the TLS data of a message (§4.1). */
    private static byte[] withOuterTlvs(byte[] message, byte[] tlvs) {
        int flags = message[0] & 0xFF;
        int offset = (flags & TlsTunnel.FLAG_LENGTH) != 0 ? 5 : 1;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(flags | TlsTunnel.FLAG_OUTER_TLVS | Teap.TEAP_VERSION);
        out.write(message, 1, offset - 1);
        out.writeBytes(new byte[] {0, 0, (byte) (tlvs.length >>> 8), (byte) tlvs.length});
        out.write(message, offset, message.length - offset);
        out.writeBytes(tlvs);
        return out.toByteArray();
    }

    @Test
    void onlyTheOuterTlvsOfThePeersFirstMessageAreBound() throws Exception {
        byte[] first = Teap.tlv(Teap.TLV_AUTHORITY_ID, "peer-first".getBytes(StandardCharsets.UTF_8));
        byte[] later = Teap.tlv(Teap.TLV_AUTHORITY_ID, "peer-later".getBytes(StandardCharsets.UTF_8));
        int[] messages = {0};
        tamper = m -> withOuterTlvs(m, messages[0]++ == 0 ? first : later);
        TeapPeer peer = alice();
        peer.outerTlvs = first;
        assertSucceeded(converse(teap(List.of(Teap.BASIC)), "TLSv1.3", peer), peer);
        assertThat(messages[0]).isGreaterThan(2);

        messages[0] = 0;
        TeapPeer binding = alice();
        binding.outerTlvs = later; // the peer binds other Outer TLVs than those of its first message
        assertThat(converse(teap(List.of(Teap.BASIC)), "TLSv1.2", binding).success())
                .isFalse();
        assertThat(binding.serverBindingValid)
                .as("the server's MAC covers the first message's Outer TLVs too")
                .isFalse();
    }

    @Test
    void identityTypesChainTheInnerMethods() throws Exception {
        Teap both = teap(List.of(Teap.BASIC), List.of(Teap.IDENTITY_MACHINE, Teap.IDENTITY_USER));
        TeapPeer peer = alice();
        assertSucceeded(converse(both, "TLSv1.3", peer), peer);
        assertThat(peer.bindings).as("one binding per identity type").isEqualTo(2);
        assertThat(peer.basicAnswers).isEqualTo(2);
        assertThat(both.innerIdentity()).as("the user, after the machine").isEqualTo("alice");

        Teap machine = teap(EapConfig.DEFAULT_TEAP_INNER, List.of(Teap.IDENTITY_MACHINE));
        TeapPeer device = alice();
        assertSucceeded(converse(machine, "TLSv1.2", device), device);
        assertThat(machine.innerIdentity()).as("a machine alone").isEqualTo("alice");

        TeapPeer noIntermediate = alice();
        noIntermediate.rewrite = without(Teap.TLV_INTERMEDIATE_RESULT);
        assertFailed(converse(
                teap(List.of(Teap.BASIC), List.of(Teap.IDENTITY_MACHINE, Teap.IDENTITY_USER)),
                "TLSv1.3",
                noIntermediate));
        assertThat(noIntermediate.bindings)
                .as("the first round's binding needs a successful Intermediate-Result")
                .isEqualTo(1);
    }
}
