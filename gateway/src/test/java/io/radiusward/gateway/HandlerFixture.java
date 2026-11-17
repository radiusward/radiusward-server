/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.Md4;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.collections.IntHashSet;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * What the store handler's tests share: in-memory identity stores, a handler built over them with a fixed clock, and
 * the requests and reply readers the tests of each part (users, passwords, MS-CHAP, EAP, admission) drive it with.
 * The tests go through {@link StoreAccessHandler#handle}, as a worker does, so they also check how the parts are wired.
 */
abstract class HandlerFixture {

    static final Dictionary DICTIONARY = DictionaryLoader.loadBundled();
    static final byte[] SECRET = AuthAgentTest.SECRET;

    /** An in-memory store counting look-ups; {@code down} makes it unavailable. */
    static final class MemoryStore implements IdentityStore {
        final Map<String, UserRecord> users = new HashMap<>();
        final AtomicInteger lookups = new AtomicInteger();
        volatile boolean down;

        MemoryStore user(
                String name, List<AttributeItem> check, List<AttributeItem> reply, UserRecord.Group... groups) {
            users.put(name, new UserRecord(name, check, reply, List.of(groups)));
            return this;
        }

        @Override
        public Optional<UserRecord> lookup(String userName) throws StoreUnavailableException {
            lookups.incrementAndGet();
            if (down) {
                throw new StoreUnavailableException("down");
            }
            return Optional.ofNullable(users.get(userName));
        }

        @Override
        public void close() {}
    }

    static AttributeItem item(String attribute, String op, String value) {
        return new AttributeItem(attribute, op, value);
    }

    final long[] now = {1_800_000_000_000L}; // 2027-01-15
    final MemoryStore main = new MemoryStore();
    final MemoryStore second = new MemoryStore();
    final AccessContext context = new AccessContext();
    final Map<String, IntHashSet> replyVendors = new HashMap<>();
    final Map<String, Boolean> mschap = new HashMap<>();
    final Map<String, io.radiusward.auth.CredentialVerifier> verifiers = new HashMap<>();
    final Map<String, String> storeVerifiers = new HashMap<>();
    final Map<String, Boolean> chapStores = new HashMap<>();
    EapConfig eapConfig = EapConfig.DEFAULT;

    StoreAccessHandler handler(Map<String, Boolean> chap, Map<String, List<String>> perNas) {
        return new StoreAccessHandler(stores(chap, perNas), DICTIONARY, () -> now[0]);
    }

    AuthStores stores(Map<String, Boolean> chap, Map<String, List<String>> perNas) {
        Map<String, IdentityStore> stores = new java.util.LinkedHashMap<>();
        stores.put("main", main);
        stores.put("second", second);
        return new AuthStores(
                stores,
                List.of("main", "second"),
                perNas,
                chap,
                Duration.ofSeconds(5),
                1000,
                12,
                replyVendors,
                mschap,
                verifiers,
                storeVerifiers,
                eapConfig);
    }

    StoreAccessHandler handler() {
        return handler(Map.of(), Map.of());
    }

    /** Runs the handler on a PAP (or CHAP) request; returns the code. */
    int pap(StoreAccessHandler handler, String user, String password, byte[]... extra) {
        return handle(handler, AccessRequestBuilder.pap(user, password, extra));
    }

    int handle(StoreAccessHandler handler, byte[] request) {
        context.reset(
                new UnsafeBuffer(request),
                0,
                request.length,
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
                        .clients()
                        .iterator()
                        .next());
        return handler.handle(context);
    }

    /** The reply attributes the handler wrote, as a packet to inspect. */
    RadiusPacket reply() {
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

    long sessionTimeout() {
        RadiusPacket reply = reply();
        int at = reply.findAttribute(27);
        return at < 0 ? -1 : reply.buffer().getInt(at + 2, java.nio.ByteOrder.BIG_ENDIAN) & 0xFFFFFFFFL;
    }

    String totpCode(int stepsAhead) {
        return Totp.code(TotpTest.SEED, now[0] / 1000 / 30 + stepsAhead, 6);
    }

    byte[] state() {
        RadiusPacket reply = reply();
        int at = reply.findAttribute(24);
        assertThat(at).as("State").isPositive();
        byte[] state = new byte[(reply.buffer().getByte(at + 1) & 0xFF) - 2];
        reply.buffer().getBytes(at + 2, state);
        return state;
    }

    static List<String> filterIds(RadiusPacket p) {
        List<String> ids = new java.util.ArrayList<>();
        for (int pos = p.attributesOffset(); pos < p.attributesEnd(); ) {
            int len = p.buffer().getByte(pos + 1) & 0xFF;
            if ((p.buffer().getByte(pos) & 0xFF) == 11) {
                ids.add(p.buffer().getStringWithoutLengthUtf8(pos + 2, len - 2));
            }
            pos += len;
        }
        return ids;
    }

    static NasClient nas() {
        return AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
                .clients()
                .iterator()
                .next();
    }

    /** Vendor ids of the Vendor-Specific attributes, in order. */
    static List<Integer> vendors(RadiusPacket p) {
        List<Integer> ids = new java.util.ArrayList<>();
        for (int pos = p.attributesOffset(); pos < p.attributesEnd(); ) {
            int len = p.buffer().getByte(pos + 1) & 0xFF;
            if ((p.buffer().getByte(pos) & 0xFF) == 26) {
                ids.add(p.buffer().getInt(pos + 2, java.nio.ByteOrder.BIG_ENDIAN));
            }
            pos += len;
        }
        return ids;
    }

    /** Records what the handler asks and answers with {@link #answer}. */
    static final class FakeLimits implements SessionLimits {
        int answer = GRANTED;
        int calls;
        long user;
        long device;
        int maxDevices;

        @Override
        public int reserve(long userKey, long deviceKey, int maxDevices) {
            calls++;
            this.user = userKey;
            this.device = deviceKey;
            this.maxDevices = maxDevices;
            return answer;
        }
    }

    static final byte[] AUTH_CHALLENGE = MsChapTest.hex("5B5D7C7D7B3F2F3E3C2C602132262628");
    static final byte[] PEER_CHALLENGE = MsChapTest.hex("21402324255E262A28295F2B3A337C7E");

    /** An MS-CHAPv2 request as a client computes it (RFC 2759), for {@code user} with {@code password}. */
    static byte[] msChap2(String user, String password) {
        byte[] name = user.getBytes(StandardCharsets.US_ASCII);
        byte[] hash = MsChap.challengeHash(PEER_CHALLENGE, AUTH_CHALLENGE, MsChap.v2UserName(name));
        byte[] response = new byte[50];
        response[0] = 7; // ident
        System.arraycopy(PEER_CHALLENGE, 0, response, 2, 16);
        System.arraycopy(MsChap.challengeResponse(hash, MsChap.ntHash(password)), 0, response, 26, 24);
        return msChapRequest(user, AUTH_CHALLENGE, 25, response);
    }

    static byte[] msChap1(String user, String password, boolean useNt) {
        byte[] challenge = MsChapTest.hex("102DB5DF085D3041");
        byte[] response = new byte[50];
        response[0] = 3;
        response[1] = (byte) (useNt ? 1 : 0);
        System.arraycopy(MsChap.challengeResponse(challenge, MsChap.ntHash(password)), 0, response, 26, 24);
        return msChapRequest(user, challenge, 1, response);
    }

    static byte[] msChapRequest(String user, byte[] challenge, int responseType, byte[] response) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        byte[] auth = new byte[16];
        ThreadLocalRandom.current().nextBytes(auth);
        int length = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, 1)
                .authenticator(auth)
                .attribute(1, user)
                .vendorAttribute(311, 11, challenge)
                .vendorAttribute(311, responseType, response)
                .finish();
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** The values of Microsoft attribute {@code type} in the reply. */
    List<byte[]> microsoft(int type) {
        RadiusPacket p = reply();
        List<byte[]> values = new java.util.ArrayList<>();
        for (int pos = p.attributesOffset(); pos < p.attributesEnd(); ) {
            int len = p.buffer().getByte(pos + 1) & 0xFF;
            if ((p.buffer().getByte(pos) & 0xFF) == 26
                    && p.buffer().getInt(pos + 2, java.nio.ByteOrder.BIG_ENDIAN) == 311
                    && (p.buffer().getByte(pos + 6) & 0xFF) == type) {
                byte[] v = new byte[(p.buffer().getByte(pos + 7) & 0xFF) - 2];
                p.buffer().getBytes(pos + 8, v);
                values.add(v);
            }
            pos += len;
        }
        return values;
    }

    /** RFC 2548 §2.4.2 in reverse, as the NAS does it. */
    static byte[] decryptKey(byte[] value, byte[] requestAuthenticator) {
        return MsChap.decryptKey(value, SECRET, requestAuthenticator);
    }

    /** A directory knowing "User" with password "clientPass", as a domain controller would check it. */
    static final class FakeVerifier implements io.radiusward.auth.CredentialVerifier {
        boolean down;
        int calls;
        String lastUser;

        @Override
        public Result verifyPassword(String userName, byte[] password) throws StoreUnavailableException {
            calls++;
            lastUser = userName;
            if (down) {
                throw new StoreUnavailableException("dc down");
            }
            return new String(password, StandardCharsets.UTF_8).equals("clientPass")
                    ? Result.accepted(null)
                    : Result.REJECTED;
        }

        @Override
        public Result verifyMsChap(String userName, byte[] challenge, byte[] ntResponse, boolean v2)
                throws StoreUnavailableException {
            calls++;
            lastUser = userName;
            if (down) {
                throw new StoreUnavailableException("dc down");
            }
            byte[] hash = MsChap.ntHash("clientPass");
            return Arrays.equals(MsChap.challengeResponse(challenge, hash), ntResponse)
                    ? Result.accepted(Md4.digest(hash))
                    : Result.REJECTED;
        }

        @Override
        public java.util.Map<String, Long> counters() {
            return java.util.Map.of("calls", (long) calls);
        }

        @Override
        public void close() {}
    }

    /** An Access-Request carrying one EAP response, with a State when the conversation goes on. */
    static byte[] eapRequest(EapPacket eap, byte[] state) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, 1)
                .authenticator(new byte[16]);
        enc.attribute(1, "alice");
        eap.writeTo(enc);
        if (state != null) {
            enc.attribute(24, state);
        }
        return Arrays.copyOf(buffer.byteArray(), enc.finish());
    }

    /** The reply's EAP packet and State. */
    EapPacket replyEap() {
        return EapPacket.from(reply());
    }

    byte[] replyState() {
        RadiusPacket r = reply();
        int at = r.findAttribute(24);
        if (at < 0) {
            return null;
        }
        byte[] state = new byte[(r.buffer().getByte(at + 1) & 0xFF) - 2];
        r.buffer().getBytes(at + 2, state);
        return state;
    }

    static EapPacket identity(int id, String name) {
        return new EapPacket(
                EapPacket.CODE_RESPONSE, id, EapPacket.TYPE_IDENTITY, name.getBytes(StandardCharsets.UTF_8));
    }

    /** An EAP-MD5 response to {@code challenge} (RFC 3748 §5.4). */
    static EapPacket md5Response(EapPacket challenge, String password) throws Exception {
        java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5");
        md5.update((byte) challenge.identifier());
        md5.update(password.getBytes(StandardCharsets.UTF_8));
        md5.update(challenge.data(), 1, challenge.data()[0] & 0xFF);
        byte[] data = new byte[17];
        data[0] = 16;
        System.arraycopy(md5.digest(), 0, data, 1, 16);
        return new EapPacket(EapPacket.CODE_RESPONSE, challenge.identifier(), EapPacket.TYPE_MD5, data);
    }

    /** Access-Requests for the handler tests (no Message-Authenticator: the agent checks that, not the handler). */
    static final class AccessRequestBuilder {
        static byte[] uint32(int type, long value) {
            return new byte[] {
                (byte) type, 6, (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value
            };
        }

        static byte[] attribute(int type, byte[] value) {
            byte[] attribute = new byte[2 + value.length];
            attribute[0] = (byte) type;
            attribute[1] = (byte) attribute.length;
            System.arraycopy(value, 0, attribute, 2, value.length);
            return attribute;
        }

        static byte[] ipv4(int type, int a, int b, int c, int d) {
            return new byte[] {(byte) type, 6, (byte) a, (byte) b, (byte) c, (byte) d};
        }

        static byte[] pap(String user, String password, byte[]... extra) {
            byte[] request = AuthAgentTest.accessRequest(1, password, false, false);
            return withUser(request, user, extra);
        }

        static byte[] userOnly(String user) {
            UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
            byte[] auth = new byte[16];
            ThreadLocalRandom.current().nextBytes(auth);
            int length = new RadiusPacketEncoder()
                    .wrap(buffer, 0)
                    .header(RadiusCode.ACCESS_REQUEST, 1)
                    .authenticator(auth)
                    .attribute(1, user)
                    .finish();
            return Arrays.copyOf(buffer.byteArray(), length);
        }

        static byte[] chapSafe(String user, String password) {
            try {
                return chap(user, password);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        static byte[] chap(String user, String password) throws Exception {
            byte[] challenge = new byte[16];
            ThreadLocalRandom.current().nextBytes(challenge);
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update((byte) 7);
            md5.update(password.getBytes(StandardCharsets.UTF_8));
            md5.update(challenge);
            byte[] response = new byte[17];
            response[0] = 7;
            System.arraycopy(md5.digest(), 0, response, 1, 16);
            UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
            int length = new RadiusPacketEncoder()
                    .wrap(buffer, 0)
                    .header(RadiusCode.ACCESS_REQUEST, 1)
                    .authenticator(new byte[16])
                    .attribute(1, user)
                    .attribute(3, response)
                    .attribute(60, challenge)
                    .finish();
            return Arrays.copyOf(buffer.byteArray(), length);
        }

        /** Replaces the User-Name ("nemo") of a request built by the agent test and appends attributes. */
        private static byte[] withUser(byte[] request, String user, byte[]... extra) {
            UnsafeBuffer in = new UnsafeBuffer(request);
            RadiusPacket p = new RadiusPacket();
            p.wrap(in, 0, request.length);
            UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
            RadiusPacketEncoder enc = new RadiusPacketEncoder()
                    .wrap(buffer, 0)
                    .header(RadiusCode.ACCESS_REQUEST, 1)
                    .authenticator(in, 4);
            enc.attribute(1, user);
            for (int pos = p.attributesOffset(); pos < p.attributesEnd(); ) {
                int len = in.getByte(pos + 1) & 0xFF;
                if ((in.getByte(pos) & 0xFF) != 1) {
                    enc.rawAttribute(in, pos);
                }
                pos += len;
            }
            for (byte[] attribute : extra) {
                enc.rawAttribute(new UnsafeBuffer(attribute), 0);
            }
            return Arrays.copyOf(buffer.byteArray(), enc.finish());
        }
    }
}
