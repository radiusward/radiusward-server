/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * A session on a NAS and the accounting events it reports: Start, Interim-Update and Stop with the attributes a NAS
 * sends (RFC 2866): Acct-Session-Id, the user, the device and NAS identity, Event-Timestamp, session time and octets
 * (with Gigawords beyond 4 GiB), the terminate cause.
 *
 * <pre>{@code
 * AccountingSession s = new AccountingSession("s-1").user("alice").callingStationId("aa-bb-cc-dd-ee-ff");
 * client.send(s.start());
 * AccountingEvent interim = s.interim(Duration.ofMinutes(5), 1_000_000, 4_000_000);
 * client.send(interim);
 * client.send(interim.delay(3));              // the NAS's retransmission: counted once
 * client.send(s.stop(Duration.ofMinutes(10), 2_000_000, 8_000_000, TerminateCause.USER_REQUEST));
 * }</pre>
 */
public final class AccountingSession {

    private final String sessionId;
    private final List<byte[]> identity = new ArrayList<>(); // after Acct-Session-Id, in the order set
    private Clock clock = Clock.systemUTC();

    public AccountingSession(String acctSessionId) {
        if (acctSessionId.isEmpty()) {
            throw new IllegalArgumentException("an Acct-Session-Id is required");
        }
        this.sessionId = acctSessionId;
    }

    public String sessionId() {
        return sessionId;
    }

    public AccountingSession user(String userName) {
        return text(1, userName);
    }

    /** The device, e.g. its MAC address. */
    public AccountingSession callingStationId(String id) {
        return text(31, id);
    }

    /** The access point or port, e.g. {@code AP-MAC:SSID}. */
    public AccountingSession calledStationId(String id) {
        return text(30, id);
    }

    public AccountingSession nasIdentifier(String id) {
        return text(32, id);
    }

    public AccountingSession nasIpAddress(String address) {
        return address(4, address);
    }

    public AccountingSession nasPort(long port) {
        identity.add(AccountingEvent.uint32(5, port));
        return this;
    }

    public AccountingSession framedIpAddress(String address) {
        return address(8, address);
    }

    /** Acct-Multi-Session-Id: links the sessions of one client across access points or links. */
    public AccountingSession multiSessionId(String id) {
        return text(50, id);
    }

    /** Another attribute in every event of the session. */
    public AccountingSession attribute(int type, String value) {
        return text(type, value);
    }

    /** Another vendor attribute in every event of the session, e.g. {@code vendor(9, 1, "a=b")} (Cisco-AVPair). */
    public AccountingSession vendor(int vendorId, int vendorType, String value) {
        identity.add(AccountingEvent.vendor(vendorId, vendorType, value.getBytes(StandardCharsets.UTF_8)));
        return this;
    }

    /** Where Event-Timestamp comes from (default: the system clock). */
    public AccountingSession clock(Clock clock) {
        this.clock = clock;
        return this;
    }

    /** Accounting-Start. */
    public AccountingEvent start() {
        return event(AccountingEvent.START, List.of());
    }

    /** Interim-Update with the session time and the octets so far (input: from the user, output: to the user). */
    public AccountingEvent interim(Duration sessionTime, long inputOctets, long outputOctets) {
        return event(AccountingEvent.INTERIM_UPDATE, usage(sessionTime, inputOctets, outputOctets));
    }

    /** Accounting-Stop with the totals and why the session ended. */
    public AccountingEvent stop(Duration sessionTime, long inputOctets, long outputOctets, TerminateCause cause) {
        List<byte[]> attributes = usage(sessionTime, inputOctets, outputOctets);
        attributes.add(AccountingEvent.uint32(49, cause.value()));
        return event(AccountingEvent.STOP, attributes);
    }

    private AccountingEvent event(int statusType, List<byte[]> usage) {
        List<byte[]> attributes = new ArrayList<>();
        attributes.add(AccountingEvent.attribute(44, sessionId.getBytes(StandardCharsets.UTF_8)));
        attributes.addAll(identity);
        attributes.add(AccountingEvent.uint32(55, clock.instant().getEpochSecond()));
        attributes.addAll(usage);
        return AccountingEvent.of(statusType, attributes);
    }

    private static List<byte[]> usage(Duration sessionTime, long inputOctets, long outputOctets) {
        if (sessionTime.isNegative() || inputOctets < 0 || outputOctets < 0) {
            throw new IllegalArgumentException("session time and octets cannot be negative");
        }
        List<byte[]> a = new ArrayList<>();
        a.add(AccountingEvent.uint32(46, sessionTime.toSeconds()));
        a.add(AccountingEvent.uint32(42, inputOctets & 0xFFFF_FFFFL));
        a.add(AccountingEvent.uint32(43, outputOctets & 0xFFFF_FFFFL));
        if (inputOctets >>> 32 != 0) {
            a.add(AccountingEvent.uint32(52, inputOctets >>> 32)); // Acct-Input-Gigawords (RFC 2869 §5.1)
        }
        if (outputOctets >>> 32 != 0) {
            a.add(AccountingEvent.uint32(53, outputOctets >>> 32));
        }
        return a;
    }

    private AccountingSession text(int type, String value) {
        identity.add(AccountingEvent.attribute(type, value.getBytes(StandardCharsets.UTF_8)));
        return this;
    }

    private AccountingSession address(int type, String address) {
        byte[] ip;
        try {
            ip = InetAddress.ofLiteral(address).getAddress();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("not an IP address: " + address, e);
        }
        if (ip.length != 4) {
            throw new IllegalArgumentException("an IPv4 address is expected: " + address);
        }
        identity.add(AccountingEvent.attribute(type, ip));
        return this;
    }
}
