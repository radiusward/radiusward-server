/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.eap.EapPacket;
import java.util.List;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** EAP in RADIUS: conversations, rounds, failures, bounds and SIM subscribers (RFC 3579, ADR 0026). */
class EapAuthenticatorTest extends HandlerFixture {

    @Test
    void eapMd5ConversationEndsInSuccessWithTheUsersReplyItems() throws Exception {
        main.user(
                "alice", List.of(item("Cleartext-Password", ":=", "arctangent")), List.of(item("Filter-Id", "=", "x")));
        chapStores.put("main", true);
        StoreAccessHandler h = handler(chapStores, Map.of());

        assertThat(handle(h, eapRequest(identity(5, "alice"), null))).isEqualTo(AccessHandler.CHALLENGE);
        EapPacket challenge = replyEap();
        byte[] state = replyState();
        assertThat(challenge.code()).isEqualTo(EapPacket.CODE_REQUEST);
        assertThat(challenge.type()).isEqualTo(EapPacket.TYPE_MD5);
        assertThat(challenge.identifier()).isEqualTo(6);
        assertThat(state).hasSize(16);
        assertThat(h.eapConversations()).isEqualTo(1);

        byte[] answer = eapRequest(md5Response(challenge, "arctangent"), state);
        assertThat(handle(h, answer)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(replyEap().code()).isEqualTo(EapPacket.CODE_SUCCESS);
        assertThat(replyEap().identifier()).isEqualTo(6);
        assertThat(reply().findAttribute(11)).as("Filter-Id").isPositive();
        assertThat(h.eapConversations()).isZero();

        assertThat(handle(h, answer)).as("a used State").isEqualTo(AccessHandler.REJECT);
        assertThat(replyEap().code()).isEqualTo(EapPacket.CODE_FAILURE);
    }

    @Test
    void eapFailures() throws Exception {
        main.user("alice", List.of(item("Cleartext-Password", ":=", "arctangent")), List.of())
                .user("plain", List.of(item("Cleartext-Password", ":=", "pw")), List.of());
        chapStores.put("main", true);
        StoreAccessHandler h = handler(chapStores, Map.of());

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket challenge = replyEap();
        assertThat(handle(h, eapRequest(md5Response(challenge, "wrong"), replyState())))
                .isEqualTo(AccessHandler.REJECT);
        assertThat(replyEap().code()).as("EAP-Failure in every EAP Reject").isEqualTo(EapPacket.CODE_FAILURE);

        assertThat(handle(h, eapRequest(identity(1, "nobody"), null))).isEqualTo(AccessHandler.REJECT);
        assertThat(replyEap().code()).isEqualTo(EapPacket.CODE_FAILURE);

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket c2 = replyEap();
        byte[] s2 = replyState();
        EapPacket otherId =
                new EapPacket(EapPacket.CODE_RESPONSE, c2.identifier() + 1, EapPacket.TYPE_MD5, new byte[17]);
        assertThat(handle(h, eapRequest(otherId, s2)))
                .as("an answer to another request")
                .isEqualTo(AccessHandler.DROP);

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket c3 = replyEap();
        byte[] s3 = replyState();
        now[0] += 31_000;
        assertThat(handle(h, eapRequest(md5Response(c3, "arctangent"), s3)))
                .as("expired")
                .isEqualTo(AccessHandler.REJECT);

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket c4 = replyEap();
        EapPacket nak = new EapPacket(EapPacket.CODE_RESPONSE, c4.identifier(), EapPacket.TYPE_NAK, new byte[] {13});
        assertThat(handle(h, eapRequest(nak, replyState())))
                .as("the peer wants EAP-TLS, which is not offered")
                .isEqualTo(AccessHandler.REJECT);

        assertThat(handle(
                        h,
                        eapRequest(new EapPacket(EapPacket.CODE_RESPONSE, 1, EapPacket.TYPE_MD5, new byte[17]), null)))
                .as("not Identity, no State")
                .isEqualTo(AccessHandler.REJECT);
        byte[] broken = eapRequest(identity(1, "alice"), null);
        broken[broken.length - 1 - "alice".length() - 2] = 0x7F; // EAP length no longer matches
        assertThat(handle(h, broken)).as("malformed EAP is discarded").isEqualTo(AccessHandler.DROP);

        StoreAccessHandler noCleartext = handler();
        handle(noCleartext, eapRequest(identity(1, "plain"), null));
        EapPacket c5 = replyEap();
        assertThat(handle(noCleartext, eapRequest(md5Response(c5, "pw"), replyState())))
                .as("EAP-MD5 needs the store's chap opt-in, like CHAP")
                .isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void eapRoundsAndConversationsAreBounded() throws Exception {
        main.user("alice", List.of(item("Cleartext-Password", ":=", "arctangent")), List.of());
        chapStores.put("main", true);
        eapConfig = new EapConfig(List.of("md5"), EapConfig.DEFAULT.timeout(), 1, 1, null);
        StoreAccessHandler h = handler(chapStores, Map.of());
        assertThat(handle(h, eapRequest(identity(1, "alice"), null))).isEqualTo(AccessHandler.CHALLENGE);
        EapPacket challenge = replyEap();
        byte[] state = replyState();
        assertThat(handle(h, eapRequest(identity(1, "alice"), null)))
                .as("auth.eap.conversations = 1, and it is taken")
                .isEqualTo(AccessHandler.DROP);
        assertThat(handle(h, eapRequest(md5Response(challenge, "arctangent"), state)))
                .as("auth.eap.rounds = 1: the answer is a second round")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(h.metrics().eapOutcome("md5", "too_many_rounds")).isEqualTo(1);
    }

    @Test
    void anEapMethodThatCannotStartIsARejectNotACrash() {
        // EapConfig.from refuses PEAP without auth.eap.tls.certificate; made directly, the check is bypassed
        main.user("alice", List.of(item("Cleartext-Password", ":=", "arctangent")), List.of());
        eapConfig = new EapConfig(List.of("peap"), EapConfig.DEFAULT.timeout(), 10, 50, null);
        StoreAccessHandler h = handler();
        assertThat(handle(h, eapRequest(identity(1, "alice"), null))).isEqualTo(AccessHandler.REJECT);
        assertThat(replyEap().code()).isEqualTo(EapPacket.CODE_FAILURE);
        assertThat(h.eapConversations()).isZero();
    }

    @Test
    void eapWithoutACredentialToCheckAndEapThatIsNotUnderstood() throws Exception {
        main.user("guest", List.of(item("Auth-Type", ":=", "Accept")), List.of())
                .user("alice", List.of(item("Cleartext-Password", ":=", "arctangent")), List.of());
        chapStores.put("main", true);
        StoreAccessHandler h = handler(chapStores, Map.of());
        assertThat(handle(h, eapRequest(identity(3, "guest"), null)))
                .as("Auth-Type := Accept: EAP-Success right away")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(replyEap().code()).isEqualTo(EapPacket.CODE_SUCCESS);
        assertThat(handle(h, eapRequest(identity(1, " \0 "), null)))
                .as("an empty identity")
                .isEqualTo(AccessHandler.REJECT);

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket challenge = replyEap();
        EapPacket otherType =
                new EapPacket(EapPacket.CODE_RESPONSE, challenge.identifier(), EapTls.TYPE, new byte[] {0});
        assertThat(handle(h, eapRequest(otherType, replyState())))
                .as("a response of another method than the one running")
                .isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void simSubscribersNeedUsableKeys() {
        main.user("001010000000001", List.of(), List.of())
                .user(
                        "001010000000002",
                        List.of(item("SIM-Ki", ":=", "0x1234"), item("SIM-OPc", ":=", "zz")),
                        List.of())
                .user(
                        "001010000000003",
                        List.of(
                                item("SIM-Ki", ":=", "465b5ce8b199b49faa5f0a2ee238a6bc"),
                                item("SIM-OPc", ":=", "cd63cb71954a9f4e48a5994e37a02baf")),
                        List.of());
        StoreAccessHandler h = handler();
        byte[] request = AccessRequestBuilder.userOnly("x");
        context.reset(
                new UnsafeBuffer(request),
                0,
                request.length,
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
                        .clients()
                        .iterator()
                        .next());
        AuthRequest auth = new StoreAccessHandler.WorkerCache().request.begin(context, AccessPolicies.NONE);
        EapAuthenticator eap = h.eap();
        assertThat(eap.simSubscriber(auth, "001010000000003").code()).isEqualTo(AccessHandler.ACCEPT);
        assertThat(eap.simSubscriber(auth, "001010000000001").code())
                .as("no keys")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(eap.simSubscriber(auth, "001010000000002").code())
                .as("keys that are not hex of the right length")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(eap.simSubscriber(auth, "001010000000009").code()).isEqualTo(AccessHandler.REJECT);
        main.down = true;
        assertThat(eap.simSubscriber(
                                new StoreAccessHandler.WorkerCache().request.begin(context, AccessPolicies.NONE),
                                "001010000000003")
                        .code())
                .as("a store that is down")
                .isEqualTo(AccessHandler.DROP);
    }
}
