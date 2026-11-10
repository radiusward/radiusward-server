/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Disconnects or changes sessions on their NAS (RFC 5176, ADR 0036): finds them in the replicated state — by user, or
 * by NAS entry and Acct-Session-Id — and sends each a Disconnect- or CoA-Request with its identifying attributes,
 * over the NAS's RadSec connection if it has one, else over UDP to {@code nas.<name>.coa.address}, the entry's own
 * address, or the session's NAS-IP-Address.
 */
public final class CoaService {

    static final int NAS_IP_ADDRESS = 4;
    static final int NAS_IDENTIFIER = 32;
    static final int NAS_IPV6_ADDRESS = 95;
    static final Duration QUERY_TIMEOUT = Duration.ofSeconds(5);

    /** What happened to one session. */
    public record SessionResult(
            String nas, String acctSessionId, String user, DynamicAuthorization.Outcome outcome, int errorCause) {}

    private final CoaConfig config;
    private final NasRegistry registry;
    private final ClusterQueries queries;
    private final DynamicAuthorization sender;
    private final Dictionary dictionary;
    private final RadsecLink radsecLink;
    private final Map<String, Integer> radsecIndex;
    private final Map<String, Integer> dtlsIndex;
    private final RadsecAgent radsec;

    CoaService(
            CoaConfig config,
            NasRegistry registry,
            ClusterQueries queries,
            DynamicAuthorization sender,
            Dictionary dictionary,
            RadsecLink radsecLink,
            Map<String, Integer> radsecIndex,
            Map<String, Integer> dtlsIndex,
            RadsecAgent radsec) {
        this.config = config;
        this.registry = registry;
        this.queries = queries;
        this.sender = sender;
        this.dictionary = dictionary;
        this.radsecLink = radsecLink;
        this.radsecIndex = radsecIndex;
        this.dtlsIndex = dtlsIndex;
        this.radsec = radsec;
    }

    private final java.util.concurrent.atomic.AtomicLong simultaneousUseDisconnected =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong simultaneousUseFailed =
            new java.util.concurrent.atomic.AtomicLong();

    CoaConfig config() {
        return config;
    }

    ClusterQueries queries() {
        return queries;
    }

    /** A Simultaneous-Use disconnect (ADR 0036): acknowledged, or not. */
    void countSimultaneousUse(boolean acknowledged) {
        (acknowledged ? simultaneousUseDisconnected : simultaneousUseFailed).incrementAndGet();
    }

    void writeMetrics(io.radiusward.common.management.PrometheusWriter w, String gateway) {
        w.counter(
                "radiusward_gateway_simultaneous_use_disconnects_total",
                "Oldest sessions disconnected to make room for a new one (coa.simultaneous.use = disconnect-oldest)");
        w.sample(simultaneousUseDisconnected.get(), "gateway", gateway, "result", "acknowledged");
        w.sample(simultaneousUseFailed.get(), "gateway", gateway, "result", "failed");
    }

    /** Disconnect-Request to every active session of the user. */
    public List<SessionResult> disconnectUser(String user) throws TimeoutException {
        return toUser(user, DynamicAuthorization.DISCONNECT_REQUEST, List.of());
    }

    /** CoA-Request with these attributes to every active session of the user. */
    public List<SessionResult> changeUser(String user, List<AttributeItem> attributes) throws TimeoutException {
        return toUser(user, DynamicAuthorization.COA_REQUEST, attributes);
    }

    /** Disconnect-Request (or CoA-Request with attributes) to one session of a NAS entry without device identity. */
    public List<SessionResult> toSession(String nasName, String acctSessionId, List<AttributeItem> attributes)
            throws TimeoutException {
        encode(attributes);
        NasClient nas = registry.clients().stream()
                .filter(c -> c.name().equals(nasName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("no NAS entry " + nasName));
        if (nas.identifiesDevices()) {
            throw new IllegalArgumentException(
                    "NAS entry " + nasName + " tells devices apart (identity): address its sessions by user");
        }
        EventKeys keys = new EventKeys();
        UnsafeBuffer id = new UnsafeBuffer(acctSessionId.getBytes(StandardCharsets.UTF_8));
        keys.compute(nas.id(), 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
        ClusterQueries.Session s = queries.session(keys.sessionHi(), keys.sessionLo(), QUERY_TIMEOUT);
        if (s == null || !s.active()) {
            return List.of();
        }
        int code = attributes.isEmpty() ? DynamicAuthorization.DISCONNECT_REQUEST : DynamicAuthorization.COA_REQUEST;
        return join(List.of(s), List.of(send(s, code, attributes)));
    }

    private List<SessionResult> toUser(String user, int code, List<AttributeItem> attributes) throws TimeoutException {
        encode(attributes); // a wrong attribute is the caller's mistake, before any session is asked for
        byte[] name = user.getBytes(StandardCharsets.UTF_8);
        List<ClusterQueries.Session> sessions =
                queries.userSessions(UserKeys.user(new UnsafeBuffer(name), 0, name.length), QUERY_TIMEOUT);
        List<CompletableFuture<DynamicAuthorization.Result>> results = new ArrayList<>();
        for (ClusterQueries.Session s : sessions) {
            results.add(send(s, code, attributes));
        }
        return join(sessions, results);
    }

    private List<SessionResult> join(
            List<ClusterQueries.Session> sessions, List<CompletableFuture<DynamicAuthorization.Result>> results) {
        List<SessionResult> out = new ArrayList<>();
        for (int i = 0; i < sessions.size(); i++) {
            ClusterQueries.Session s = sessions.get(i);
            DynamicAuthorization.Result r = results.get(i)
                    .exceptionally(e -> new DynamicAuthorization.Result(DynamicAuthorization.Outcome.UNREACHABLE, 0))
                    .join();
            NasClient nas = nasOf(s);
            out.add(new SessionResult(
                    nas == null ? null : nas.name(), s.attribute(44), s.attribute(1), r.outcome(), r.errorCause()));
        }
        return out;
    }

    /**
     * A CoA or Disconnect-Request a home server sent for one of its users (ADR 0043), its attributes as they came
     * (without Proxy-State and Message-Authenticator): to the NAS of the user's active session (the one with its
     * Acct-Session-Id, if given), else to the NAS entry of its NAS-IP-Address. {@code null} when no session or NAS
     * is found.
     */
    CompletableFuture<DynamicAuthorization.Result> relay(int code, byte[] attributes) throws TimeoutException {
        byte[] user = raw(attributes, 1);
        byte[] sessionId = raw(attributes, 44);
        if (user != null) {
            for (ClusterQueries.Session s :
                    queries.userSessions(UserKeys.user(new UnsafeBuffer(user), 0, user.length), QUERY_TIMEOUT)) {
                String id = s.attribute(44);
                if (sessionId == null || (id != null && id.equals(new String(sessionId, StandardCharsets.UTF_8)))) {
                    NasClient nas = nasOf(s);
                    return nas == null ? null : deliver(nas, s, code, attributes);
                }
            }
        }
        byte[] nasIp = raw(attributes, NAS_IP_ADDRESS);
        if (nasIp == null || nasIp.length != 4) {
            return null;
        }
        try {
            NasClient nas = registry.lookup(InetAddress.getByAddress(nasIp));
            return nas == null || nas.prefixLength() != 32 ? null : deliver(nas, null, code, attributes);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /** The value of the first attribute of this type, {@code null} if there is none. */
    static byte[] raw(byte[] attributes, int type) {
        for (int at = 0; at + 2 <= attributes.length; ) {
            int length = attributes[at + 1] & 0xFF;
            if (length < 2 || at + length > attributes.length) {
                return null;
            }
            if ((attributes[at] & 0xFF) == type) {
                return java.util.Arrays.copyOfRange(attributes, at + 2, at + length);
            }
            at += length;
        }
        return null;
    }

    /** Sends one request for a session; UNREACHABLE when it has no identity yet or no NAS to send to. */
    public CompletableFuture<DynamicAuthorization.Result> send(
            ClusterQueries.Session s, int code, List<AttributeItem> attributes) {
        NasClient nas = nasOf(s);
        if (nas == null || s.identity().length == 0) {
            return unreachable();
        }
        byte[] extra;
        try {
            extra = encode(attributes);
        } catch (IllegalArgumentException e) {
            return CompletableFuture.failedFuture(e);
        }
        return deliver(nas, s, code, attributes(s, nas, extra));
    }

    /**
     * To the NAS: over its RadSec connection or DTLS association if it has one, else over UDP to its CoA target, or
     * its address, or the session's NAS-IP-Address.
     *
     * @param s the session, {@code null} when the NAS entry has a single address
     */
    private CompletableFuture<DynamicAuthorization.Result> deliver(
            NasClient nas, ClusterQueries.Session s, int code, byte[] attrs) {
        Integer index = connected(radsecIndex.get(nas.name()));
        if (index == null) {
            index = connected(dtlsIndex.get(nas.name())); // RFC 7360 §2.4: over its DTLS association
        }
        if (index != null) {
            return sender.sendRadsec(code, attrs, index, radsecLink.clients[index].secret());
        }
        CoaConfig.Target target = config.target(nas.name());
        InetAddress address =
                target.address() != null ? target.address() : s == null ? ipv4(nas.network()) : address(nas, s);
        if (address == null) {
            return unreachable();
        }
        return sender.send(
                code,
                attrs,
                new InetSocketAddress(address, target.port()),
                target.secret() != null ? target.secret() : nas.secret());
    }

    /** The link index if the NAS has an established RadSec connection or DTLS association there. */
    private Integer connected(Integer index) {
        return index != null && radsec != null && radsec.connected(index) ? index : null;
    }

    private static CompletableFuture<DynamicAuthorization.Result> unreachable() {
        return CompletableFuture.completedFuture(
                new DynamicAuthorization.Result(DynamicAuthorization.Outcome.UNREACHABLE, 0));
    }

    /** The NAS entry of a session: by its id, or for devices behind an entry by the session's NAS-IP-Address. */
    NasClient nasOf(ClusterQueries.Session s) {
        for (NasClient c : registry.clients()) {
            if (c.id() == s.nasId()) {
                return c;
            }
        }
        InetAddress ip = nasIp(s);
        return ip == null ? null : registry.lookup(ip);
    }

    /** The entry's own address if it is a single one, else the session's NAS-IP-Address. */
    private static InetAddress address(NasClient nas, ClusterQueries.Session s) {
        if (nas.prefixLength() == 32) {
            return ipv4(nas.network());
        }
        return nasIp(s);
    }

    private static InetAddress nasIp(ClusterQueries.Session s) {
        byte[] id = s.identity();
        for (int at = 0; at + 2 <= id.length; at += id[at + 1] & 0xFF) {
            int length = id[at + 1] & 0xFF;
            if (length < 2) {
                return null;
            }
            if ((id[at] & 0xFF) == NAS_IP_ADDRESS && length == 6) {
                try {
                    return InetAddress.getByAddress(java.util.Arrays.copyOfRange(id, at + 2, at + 6));
                } catch (UnknownHostException e) {
                    return null;
                }
            }
        }
        return null;
    }

    private static InetAddress ipv4(int address) {
        try {
            return InetAddress.getByAddress(
                    new byte[] {(byte) (address >>> 24), (byte) (address >>> 16), (byte) (address >>> 8), (byte) address
                    });
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /**
     * The session's identity, a NAS-IP-Address if it names no NAS (RFC 5176 §3 asks for one) and the entry has a
     * single address, then the CoA's attributes.
     */
    private static byte[] attributes(ClusterQueries.Session s, NasClient nas, byte[] extra) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(s.identity());
        if (s.attribute(NAS_IP_ADDRESS) == null
                && s.attribute(NAS_IDENTIFIER) == null
                && s.attribute(NAS_IPV6_ADDRESS) == null
                && nas.prefixLength() == 32) {
            int a = nas.network();
            out.writeBytes(
                    new byte[] {NAS_IP_ADDRESS, 6, (byte) (a >>> 24), (byte) (a >>> 16), (byte) (a >>> 8), (byte) a});
        }
        out.writeBytes(extra);
        return out.toByteArray();
    }

    /** The CoA's attributes, encoded with the dictionary (vendor attributes as Vendor-Specific). */
    private byte[] encode(List<AttributeItem> items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (AttributeItem item : items) {
            String problem = AuthStores.replyProblem(dictionary, item);
            if (problem != null) {
                throw new IllegalArgumentException(problem);
            }
            AttributeDef def = dictionary.find(item.attribute());
            byte[] value = AttributeText.encode(def, item.value());
            if (def.vendorId() == 0) {
                if (value.length > 253) {
                    throw new IllegalArgumentException(item.attribute() + ": value too long");
                }
                out.write(def.number());
                out.write(2 + value.length);
            } else {
                if (value.length > 247) {
                    throw new IllegalArgumentException(item.attribute() + ": value too long");
                }
                out.write(26);
                out.write(8 + value.length);
                out.write(def.vendorId() >>> 24);
                out.write(def.vendorId() >>> 16);
                out.write(def.vendorId() >>> 8);
                out.write(def.vendorId());
                out.write(def.number());
                out.write(2 + value.length);
            }
            out.writeBytes(value);
        }
        return out.toByteArray();
    }
}
