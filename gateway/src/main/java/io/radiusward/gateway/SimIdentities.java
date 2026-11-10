/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Identity privacy and fast re-authentication of EAP-SIM, EAP-AKA and EAP-AKA′ (ADR 0061).
 *
 * <p>A <b>pseudonym</b> is the IMSI encrypted with AES-GCM under the current key of {@code auth.eap.sim.pseudonym.keys}:
 * the method's hint, the key's id, then 12 random bytes, the encrypted IMSI and the tag in base64url. Any gateway with
 * the keys reads it back; nothing is stored, and a retired key still decrypts while it is listed.
 *
 * <p>A <b>re-authentication identity</b> names the keys of a full authentication kept on this gateway for
 * {@code auth.eap.sim.reauth.lifetime}, at most {@code auth.eap.sim.reauth.max} times in a row; it is used once (each
 * re-authentication hands out the next one). On another gateway it is unknown, and the peer authenticates in full.
 */
final class SimIdentities {

    /** Kept keys of an authentication, for the next re-authentication. */
    record Session(
            int type, String imsi, byte[] mk, byte[] kAut, byte[] kEncr, byte[] kRe, int counter, long expires) {}

    record Key(char id, byte[] aes) {}

    static final SimIdentities NONE = new SimIdentities(List.of(), Duration.ZERO, 0, 0, System::currentTimeMillis);

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final List<Key> keys;
    private final long lifetimeMillis;
    private final int maxReauth;
    private final int capacity;
    private final LongSupplier clockMillis;
    private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();

    SimIdentities(List<Key> keys, Duration lifetime, int maxReauth, int capacity, LongSupplier clockMillis) {
        this.keys = List.copyOf(keys);
        this.lifetimeMillis = lifetime.toMillis();
        this.maxReauth = maxReauth;
        this.capacity = capacity;
        this.clockMillis = clockMillis;
    }

    /** The pseudonym hint of a method: AKA 2, SIM 3, AKA′ 7 (RFC 4186/4187 §4.1, RFC 9048). */
    static char pseudonymHint(int type) {
        return switch (type) {
            case EapSim.TYPE -> '3';
            case EapAka.TYPE_AKA_PRIME -> '7';
            default -> '2';
        };
    }

    /** The re-authentication hint: AKA 4, SIM 5, AKA′ 8. */
    static char reauthHint(int type) {
        return switch (type) {
            case EapSim.TYPE -> '5';
            case EapAka.TYPE_AKA_PRIME -> '8';
            default -> '4';
        };
    }

    boolean pseudonyms() {
        return !keys.isEmpty();
    }

    boolean reauthentication() {
        return lifetimeMillis > 0 && maxReauth > 0;
    }

    /** A fresh pseudonym for {@code imsi}, or {@code null} without keys. */
    String pseudonym(int type, String imsi) {
        if (keys.isEmpty()) {
            return null;
        }
        Key key = keys.get(0);
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.aes(), "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(new byte[] {(byte) pseudonymHint(type), (byte) key.id()});
            byte[] sealed = c.doFinal(imsi.getBytes(StandardCharsets.US_ASCII));
            byte[] all = new byte[12 + sealed.length];
            System.arraycopy(iv, 0, all, 0, 12);
            System.arraycopy(sealed, 0, all, 12, sealed.length);
            return "" + pseudonymHint(type) + key.id() + B64.encodeToString(all);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The IMSI of a pseudonym of this method (realm stripped), or {@code null} if it is none or does not decrypt. */
    String imsiOf(int type, String identity) {
        String name = withoutRealm(identity);
        if (name.length() < 3 || name.charAt(0) != pseudonymHint(type)) {
            return null;
        }
        for (Key key : keys) {
            if (key.id() != name.charAt(1)) {
                continue;
            }
            try {
                byte[] all = B64D.decode(name.substring(2));
                if (all.length < 12 + 16 + 6) {
                    return null;
                }
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.aes(), "AES"), new GCMParameterSpec(128, all, 0, 12));
                c.updateAAD(new byte[] {(byte) name.charAt(0), (byte) key.id()});
                String imsi = new String(c.doFinal(all, 12, all.length - 12), StandardCharsets.US_ASCII);
                return imsi.matches("[0-9]{6,15}") ? imsi : null;
            } catch (IllegalArgumentException | GeneralSecurityException e) {
                return null; // not base64, forged or of another key
            }
        }
        return null;
    }

    /**
     * Keeps a session for the next re-authentication and names it; {@code null} when re-authentication is off, the
     * counter reached its maximum, or the table is full.
     */
    String keep(Session session) {
        if (!reauthentication() || session.counter() >= maxReauth) {
            return null;
        }
        long now = clockMillis.getAsLong();
        if (sessions.size() >= capacity) {
            sessions.values().removeIf(s -> s.expires() <= now);
            if (sessions.size() >= capacity) {
                return null;
            }
        }
        byte[] random = new byte[15];
        RANDOM.nextBytes(random);
        String id = reauthHint(session.type()) + B64.encodeToString(random);
        sessions.put(
                id,
                new Session(
                        session.type(),
                        session.imsi(),
                        session.mk(),
                        session.kAut(),
                        session.kEncr(),
                        session.kRe(),
                        session.counter(),
                        session.counter() == 0 ? now + lifetimeMillis : session.expires()));
        return id;
    }

    /** Forgets a kept session whose authentication failed. */
    void drop(String id) {
        if (id != null) {
            sessions.remove(id);
        }
    }

    /** The session a re-authentication identity names, removed (each is used once); {@code null} if unknown. */
    Session take(int type, String identity) {
        String name = withoutRealm(identity);
        if (name.isEmpty() || name.charAt(0) != reauthHint(type)) {
            return null;
        }
        Session s = sessions.remove(name);
        return s == null || s.type() != type || s.expires() <= clockMillis.getAsLong() ? null : s;
    }

    int size() {
        return sessions.size();
    }

    static String withoutRealm(String identity) {
        int at = identity.indexOf('@');
        return at < 0 ? identity : identity.substring(0, at);
    }

    /** {@code AES/CBC} of AT_ENCR_DATA (RFC 4186 §10.12) with K_encr: the attributes, padded with AT_PADDING. */
    static byte[][] encrypt(byte[] kEncr, byte[] attributes) {
        int pad = (16 - attributes.length % 16) % 16;
        byte[] plain = new byte[attributes.length + pad];
        System.arraycopy(attributes, 0, plain, 0, attributes.length);
        if (pad > 0) {
            plain[attributes.length] = SimMessage.AT_PADDING;
            plain[attributes.length + 1] = (byte) (pad / 4);
        }
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kEncr, "AES"), new javax.crypto.spec.IvParameterSpec(iv));
            return new byte[][] {iv, c.doFinal(plain)};
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The attributes inside AT_ENCR_DATA, parsed; {@code null} if they do not decrypt or parse. */
    static SimMessage decrypt(byte[] kEncr, byte[] ivAttribute, byte[] encrAttribute) {
        if (ivAttribute == null || encrAttribute == null || ivAttribute.length != 18) {
            return null;
        }
        byte[] data = java.util.Arrays.copyOfRange(encrAttribute, 2, encrAttribute.length);
        if (data.length == 0 || data.length % 16 != 0) {
            return null;
        }
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(kEncr, "AES"),
                    new javax.crypto.spec.IvParameterSpec(ivAttribute, 2, 16));
            byte[] plain = c.doFinal(data);
            byte[] withHeader = new byte[3 + plain.length];
            System.arraycopy(plain, 0, withHeader, 3, plain.length);
            return SimMessage.parse(withHeader);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }
}
