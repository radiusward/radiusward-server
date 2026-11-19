/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * RADIUS packets for tests, signed as a NAS or a home server signs them:
 * {@code PacketBuilder.accessRequest(1).attribute(1, "alice").password("secret").messageAuthenticator().secret(s)
 * .build()}.
 *
 * <p>Attributes and the Message-Authenticator are written in the order they are added. Accounting-, CoA- and
 * Disconnect-Requests get the Request Authenticator computed from the secret (RFC 2866 §3, RFC 5176 §2.3);
 * Access-Requests and Status-Server a random one unless {@link #authenticator} fixes it, and are signed only when
 * they carry a Message-Authenticator or a User-Password. Replies are signed against their request (RFC 2865 §3).
 * The secret is needed only when something is signed or hidden.
 */
public final class PacketBuilder {

    private interface Op {
        void write(RadiusPacketEncoder encoder, Context context);
    }

    /** What an attribute needs at build time: the Request Authenticator, the secret, where the MA went. */
    private static final class Context {
        private final byte[] authenticator;
        private final byte[] secret;
        private int messageAuthenticator = -1;

        private Context(byte[] authenticator, byte[] secret) {
            this.authenticator = authenticator;
            this.secret = secret;
        }
    }

    /** Request Authenticators are unpredictable, as RFC 2865 §3 asks of a NAS. */
    private static final SecureRandom RANDOM = new SecureRandom();

    private final int code;
    private final int identifier;
    private final byte[] request;
    private final List<Op> ops = new ArrayList<>();
    private byte[] authenticator;
    private byte[] secret;

    private PacketBuilder(int code, int identifier, byte[] request) {
        this.code = code;
        this.identifier = identifier;
        this.request = request;
    }

    public static PacketBuilder accessRequest(int identifier) {
        return request(RadiusCode.ACCESS_REQUEST, identifier);
    }

    public static PacketBuilder accountingRequest(int identifier) {
        return request(RadiusCode.ACCOUNTING_REQUEST, identifier);
    }

    public static PacketBuilder statusServer(int identifier) {
        return request(RadiusCode.STATUS_SERVER, identifier);
    }

    /** A request with this code, such as CoA-Request or Disconnect-Request. */
    public static PacketBuilder request(int code, int identifier) {
        return new PacketBuilder(code, identifier & 0xFF, null);
    }

    /** A reply with this code to {@code request}: its identifier, and signed against its Request Authenticator. */
    public static PacketBuilder reply(int code, byte[] request) {
        return new PacketBuilder(code, request[1] & 0xFF, request.clone());
    }

    public PacketBuilder secret(byte[] secret) {
        this.secret = secret.clone();
        return this;
    }

    public PacketBuilder secret(String secret) {
        return secret(secret.getBytes(StandardCharsets.UTF_8));
    }

    /** The Request Authenticator of an Access-Request or Status-Server, instead of a random one. */
    public PacketBuilder authenticator(byte[] authenticator) {
        if (computed() || request != null) {
            throw new IllegalStateException("the authenticator of this packet is computed from the secret");
        }
        this.authenticator = authenticator.clone();
        return this;
    }

    public PacketBuilder attribute(int type, String value) {
        return attribute(type, value.getBytes(StandardCharsets.UTF_8));
    }

    public PacketBuilder attribute(int type, byte[] value) {
        byte[] v = value.clone();
        ops.add((e, c) -> e.attribute(type, v));
        return this;
    }

    public PacketBuilder uint32(int type, long value) {
        ops.add((e, c) -> e.uint32(type, value));
        return this;
    }

    /** An address attribute such as NAS-IP-Address or Framed-IP-Address, from dotted text. */
    public PacketBuilder ipv4(int type, String address) {
        String[] parts = address.split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("not an IPv4 address: " + address);
        }
        long value = 0;
        for (String part : parts) {
            value = value << 8 | Integer.parseInt(part);
        }
        long v = value;
        ops.add((e, c) -> e.ipv4(type, v));
        return this;
    }

    public PacketBuilder vendor(int vendorId, int vendorType, byte[] value) {
        byte[] v = value.clone();
        ops.add((e, c) -> e.vendorAttribute(vendorId, vendorType, v));
        return this;
    }

    public PacketBuilder vendor(int vendorId, int vendorType, String value) {
        return vendor(vendorId, vendorType, value.getBytes(StandardCharsets.UTF_8));
    }

    /** A whole attribute as it goes on the wire: type, length, value. */
    public PacketBuilder raw(byte[] attribute) {
        if (attribute.length < 2 || (attribute[1] & 0xFF) != attribute.length) {
            throw new IllegalArgumentException("not one attribute: its length octet must equal its size");
        }
        UnsafeBuffer a = new UnsafeBuffer(attribute.clone());
        ops.add((e, c) -> e.rawAttribute(a, 0));
        return this;
    }

    /** User-Password, hidden with the secret and the Request Authenticator (RFC 2865 §5.2). */
    public PacketBuilder password(String password) {
        return credentials(Credentials.Method.PAP, "", password);
    }

    /** CHAP-Password and CHAP-Challenge for {@code password} (RFC 2865 §5.3), with a random challenge. */
    public PacketBuilder chap(String password) {
        return credentials(Credentials.Method.CHAP, "", password);
    }

    /**
     * MS-CHAP-Challenge and MS-CHAP2-Response for {@code user} and {@code password} (RFC 2759, RFC 2548), with random
     * challenges; a domain prefix (DOMAIN&#92;user) is left out of the hash, as Windows does.
     */
    public PacketBuilder msChapV2(String user, String password) {
        return credentials(Credentials.Method.MSCHAPV2, user, password);
    }

    private PacketBuilder credentials(Credentials.Method method, String user, String password) {
        ops.add((e, c) -> new Credentials(RANDOM)
                .write(
                        e,
                        c.authenticator,
                        user,
                        password,
                        method,
                        method == Credentials.Method.PAP ? required(c.secret) : null));
        return this;
    }

    /** Whether a secret is set; {@link RadiusClient} sets its own otherwise. */
    boolean hasSecret() {
        return secret != null;
    }

    /** Message-Authenticator at this position (RFC 3579 §3.2), filled in when the packet is built. */
    public PacketBuilder messageAuthenticator() {
        ops.add((e, c) -> c.messageAuthenticator = e.messageAuthenticator());
        return this;
    }

    public byte[] build() {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder encoder = new RadiusPacketEncoder().wrap(buffer, 0).header(code, identifier);
        byte[] requestAuthenticator = authenticator;
        if (request == null && !computed()) {
            if (requestAuthenticator == null) {
                requestAuthenticator = new byte[RadiusPacket.AUTHENTICATOR_LENGTH];
                RANDOM.nextBytes(requestAuthenticator);
            }
            encoder.authenticator(requestAuthenticator);
        }
        Context context = new Context(requestAuthenticator, secret);
        for (Op op : ops) {
            op.write(encoder, context);
        }
        int length = encoder.finish();
        int ma = context.messageAuthenticator;
        RadiusAuthenticator signer = new RadiusAuthenticator();
        if (request != null) {
            signer.signResponse(
                    buffer,
                    0,
                    length,
                    ma,
                    new UnsafeBuffer(request),
                    RadiusPacket.AUTHENTICATOR_OFFSET,
                    required(secret));
        } else if (computed()) {
            signer.signAccountingRequest(buffer, 0, length, ma, required(secret));
        } else if (ma >= 0) {
            signer.signAccessRequest(buffer, 0, length, ma, required(secret));
        }
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** Requests whose Request Authenticator is an MD5 over the packet and the secret. */
    private boolean computed() {
        return request == null
                && (code == RadiusCode.ACCOUNTING_REQUEST
                        || code == RadiusCode.COA_REQUEST
                        || code == RadiusCode.DISCONNECT_REQUEST);
    }

    private static byte[] required(byte[] secret) {
        if (secret == null) {
            throw new IllegalStateException("this packet is signed or hides a password: set its secret");
        }
        return secret;
    }
}
