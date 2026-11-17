/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.Md4;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.agrona.collections.IntHashSet;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class MsChapAuthenticatorTest extends HandlerFixture {

    private static RadiusPacket packet(byte[] bytes) {
        RadiusPacket packet = new RadiusPacket();
        packet.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return packet;
    }

    @Test
    void wellFormedRequestsAreParsed() {
        MsChapAuthenticator.Request v2 = MsChapAuthenticator.request(
                packet(HandlerFixture.msChap2("User", "clientPass")), AccessRequests.METHOD_MS_CHAP2);
        assertThat(v2).isNotNull();
        assertThat(v2.v2()).isTrue();
        assertThat(v2.ident()).isEqualTo(7);
        assertThat(v2.challenge()).hasSize(8).isEqualTo(v2.challengeHash());
        assertThat(v2.ntResponse()).hasSize(24);

        MsChapAuthenticator.Request v1 = MsChapAuthenticator.request(
                packet(HandlerFixture.msChap1("User", "clientPass", true)), AccessRequests.METHOD_MS_CHAP);
        assertThat(v1).isNotNull();
        assertThat(v1.v2()).isFalse();
        assertThat(v1.ident()).isEqualTo(3);
        assertThat(v1.challengeHash()).isNull();
    }

    @Test
    void malformedRequestsAreNotParsed() {
        assertThat(MsChapAuthenticator.request(
                        packet(HandlerFixture.msChap1("User", "clientPass", false)), AccessRequests.METHOD_MS_CHAP))
                .as("v1 with the LAN Manager response only")
                .isNull();
        byte[] response = new byte[50];
        response[1] = 1;
        assertThat(MsChapAuthenticator.request(
                        packet(HandlerFixture.msChapRequest("User", new byte[16], 1, response)),
                        AccessRequests.METHOD_MS_CHAP))
                .as("v1 with a 16-byte challenge")
                .isNull();
        assertThat(MsChapAuthenticator.request(
                        packet(HandlerFixture.msChapRequest("User", new byte[16], 25, new byte[49])),
                        AccessRequests.METHOD_MS_CHAP2))
                .as("a response of 49 bytes")
                .isNull();
        assertThat(MsChapAuthenticator.request(
                        packet(HandlerFixture.msChap2("User", "clientPass")), AccessRequests.METHOD_MS_CHAP))
                .as("v2 attributes, but asked for v1: no MS-CHAP-Response")
                .isNull();
    }

    @Test
    void onlyTheTwoMsChapMethodsAreMsChap() {
        assertThat(MsChapAuthenticator.isMsChap(AccessRequests.METHOD_MS_CHAP)).isTrue();
        assertThat(MsChapAuthenticator.isMsChap(AccessRequests.METHOD_MS_CHAP2)).isTrue();
        assertThat(MsChapAuthenticator.isMsChap(AccessRequests.METHOD_PAP)).isFalse();
        assertThat(MsChapAuthenticator.isMsChap(AccessRequests.METHOD_EAP)).isFalse();
    }

    @Test
    void theErrorNamesTheFailureAndForV2TheChallenge() {
        String v2 = error(HandlerFixture.msChap2("User", "x"), AccessRequests.METHOD_MS_CHAP2);
        assertThat(v2).startsWith("\u0007E=691 R=0 C=").endsWith(" V=3");
        assertThat(error(HandlerFixture.msChap1("User", "x", true), AccessRequests.METHOD_MS_CHAP))
                .isEqualTo("\u0003E=691 R=0");
    }

    /** The MS-CHAP-Error value written in reply to {@code request}, as text. */
    private static String error(byte[] request, int method) {
        AccessContext context = new AccessContext();
        context.reset(
                new UnsafeBuffer(request),
                0,
                request.length,
                AuthAgentTest.registry(io.radiusward.gateway.NasClient.MessageAuthenticatorPolicy.OFF)
                        .clients()
                        .iterator()
                        .next());
        MsChapAuthenticator.writeError(context, method);
        byte[] reply = new byte[context.replyAttributesLength()];
        context.replyBuffer().getBytes(RadiusPacket.HEADER_LENGTH, reply);
        assertThat(reply[0] & 0xFF).as("Vendor-Specific").isEqualTo(26);
        assertThat(reply[6] & 0xFF).as("MS-CHAP-Error").isEqualTo(2);
        return new String(reply, 8, reply.length - 8, StandardCharsets.US_ASCII);
    }

    @Test
    void msChapV2AcceptsWithTheAuthenticatorResponseAndMppeKeys() throws Exception {
        main.user(
                "User",
                List.of(item("NT-Password", ":=", "44EBBA8D5312B8D611474411F56989AE")),
                List.of(item("Session-Timeout", "=", "600")));
        IntHashSet mikrotik = new IntHashSet();
        mikrotik.add(14988);
        replyVendors.put("local", mikrotik); // method attributes are never filtered by vendor
        StoreAccessHandler h = handler();
        byte[] request = msChap2("User", "clientPass");
        assertThat(handle(h, request)).isEqualTo(AccessHandler.ACCEPT);
        byte[] success = microsoft(26).get(0);
        assertThat(success[0]).as("ident of the response").isEqualTo((byte) 7);
        assertThat(new String(success, 1, success.length - 1, StandardCharsets.US_ASCII))
                .isEqualTo("S=407A5589115FD0D6209F510FE9C04566932CDA56");
        byte[] auth = Arrays.copyOfRange(request, 4, 20);
        byte[] send = microsoft(16).get(0);
        byte[] recv = microsoft(17).get(0);
        assertThat(send[0] & 0x80).as("salt high bit").isNotZero();
        assertThat(new byte[] {send[0], send[1]}).isNotEqualTo(new byte[] {recv[0], recv[1]});
        assertThat(MsChapTest.hex(decryptKey(send, auth))).isEqualTo("8B7CDC149B993A1BA118CB153F56DCCB");
        byte[] master = MsChapTest.hex("FDECE3717A8C838CB388E527AE3CDD31");
        assertThat(decryptKey(recv, auth)).isEqualTo(MsChap.serverKey(master, false));
        assertThat(reply().findAttribute(27)).as("reply items too").isPositive();
    }

    @Test
    void msChapV2FailuresCarryAnErrorAndCleartextNeedsTheOptIn() {
        main.user("User", List.of(item("NT-Password", ":=", "44EBBA8D5312B8D611474411F56989AE")), List.of())
                .user("CORP\\alice", List.of(item("Cleartext-Password", ":=", "secret")), List.of());
        StoreAccessHandler h = handler();
        assertThat(handle(h, msChap2("User", "wrongPass"))).isEqualTo(AccessHandler.REJECT);
        byte[] error = microsoft(2).get(0);
        assertThat(error[0]).isEqualTo((byte) 7);
        assertThat(new String(error, 1, error.length - 1, StandardCharsets.US_ASCII))
                .isEqualTo("E=691 R=0 C=5B5D7C7D7B3F2F3E3C2C602132262628 V=3");
        assertThat(microsoft(26)).isEmpty();

        assertThat(handle(h, msChap2("nobody", "x"))).as("unknown user").isEqualTo(AccessHandler.REJECT);
        assertThat(microsoft(2)).hasSize(1);
        assertThat(handle(h, msChap2("CORP\\alice", "secret")))
                .as("cleartext without auth.store.main.mschap")
                .isEqualTo(AccessHandler.REJECT);
        mschap.put("main", true);
        StoreAccessHandler allowed = handler();
        assertThat(handle(allowed, msChap2("CORP\\alice", "secret")))
                .as("the domain is not part of the challenge hash")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(handle(allowed, msChap2("CORP\\alice", "Secret"))).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void msChapV1() throws Exception {
        main.user("bob", List.of(item("NT-Password", ":=", "8846F7EAEE8FB117AD06BDD830B7586C")), List.of());
        StoreAccessHandler h = handler();
        byte[] request = msChap1("bob", "password", true);
        assertThat(handle(h, request)).isEqualTo(AccessHandler.ACCEPT);
        byte[] keys = microsoft(12).get(0);
        assertThat(keys).hasSize(32);
        byte[] auth = Arrays.copyOfRange(request, 4, 20);
        java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5"); // RFC 2865 §5.2 in reverse
        md5.update(SECRET);
        md5.update(auth);
        byte[] b1 = md5.digest();
        md5.update(SECRET);
        md5.update(keys, 0, 16);
        byte[] b2 = md5.digest();
        byte[] plain = new byte[32];
        for (int i = 0; i < 16; i++) {
            plain[i] = (byte) (keys[i] ^ b1[i]);
            plain[16 + i] = (byte) (keys[16 + i] ^ b2[i]);
        }
        assertThat(Arrays.copyOf(plain, 8)).as("no LAN Manager key").containsOnly(0);
        assertThat(Arrays.copyOfRange(plain, 8, 24)).isEqualTo(Md4.digest(MsChap.ntHash("password")));

        assertThat(handle(h, msChap1("bob", "wrong", true))).isEqualTo(AccessHandler.REJECT);
        byte[] error = microsoft(2).get(0);
        assertThat(new String(error, 1, error.length - 1, StandardCharsets.US_ASCII))
                .isEqualTo("E=691 R=0");
        assertThat(handle(h, msChap1("bob", "password", false)))
                .as("LAN Manager response only")
                .isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void aVerifierCannotAcceptMalformedMsChapOrMsChapWithoutASessionKey() {
        // a directory that says yes to any MS-CHAP response, but gives no key to prove it to the client
        verifiers.put("keyless", new io.radiusward.auth.CredentialVerifier() {
            @Override
            public Result verifyMsChap(String userName, byte[] challenge, byte[] ntResponse, boolean v2) {
                return Result.accepted(null);
            }

            @Override
            public void close() {}
        });
        storeVerifiers.put("main", "keyless");
        main.user("User", List.of(), List.of());
        StoreAccessHandler h = handler();
        assertThat(handle(h, msChap2("User", "anything")))
                .as("MS-CHAPv2 accepted without a session key: the client could not check the server")
                .isEqualTo(AccessHandler.REJECT);
        byte[] response = new byte[50];
        response[0] = 7;
        assertThat(handle(h, msChapRequest("User", new byte[8], 25, response)))
                .as("an MS-CHAPv2 challenge of 8 bytes is malformed: not sent to the verifier")
                .isEqualTo(AccessHandler.REJECT);
    }
}
