/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static io.radiusward.gateway.GatewayStats.Counter;

import io.radiusward.protocol.AccountingCommandEncoder;
import io.radiusward.protocol.AccountingCommittedDecoder;
import io.radiusward.protocol.AccountingRejectedDecoder;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.radius.codec.AccountingResponses;
import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.codec.VendorFormats;
import io.radiusward.radius.codec.attributes.AccountingAttributeExtractor;
import io.radiusward.radius.codec.attributes.AccountingFields;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import org.agrona.BufferUtil;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.Agent;
import org.agrona.concurrent.MessageHandler;
import org.agrona.concurrent.UnsafeBuffer;
import org.agrona.concurrent.ringbuffer.RingBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Owns the RADIUS UDP socket (ADR 0006, 0011). Per datagram: validate → NAS lookup → Request Authenticator
 * and Message-Authenticator → response cache → extract hot attributes → event keys → command into the
 * to-cluster ring buffer. Commit notifications come back through the other ring buffer; the response is
 * built from the pending slot and sent from this same socket.
 *
 * <p>Allocation-free per packet except for the sender address the JDK creates when the sender changes.
 * Never blocks: full rings or tables mean the packet is dropped and the NAS retransmits.
 */
final class UdpAgent implements Agent {

    private static final Logger LOG = LogManager.getLogger(UdpAgent.class);

    static final int COMMAND_MSG = 1;
    static final int COMMITTED_MSG = 2;
    static final int REJECTED_MSG = 3;
    /** From the cluster client: a new leader (or a new session); resubmit everything pending. */
    static final int NEW_LEADER_MSG = 4;

    private static final int RECEIVE_BATCH = 64;
    private static final int PROXY_STATE = 33;
    private static final long HOUSEKEEPING_INTERVAL_NS = 100_000_000L;

    private final GatewayConfig config;
    private final NasRegistry registry;
    private final RingBuffer toCluster;
    private final RingBuffer fromCluster;
    private final GatewayStats stats;
    private final NanoClock clock;

    private final ByteBuffer receiveBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH + 64, 64);
    private final UnsafeBuffer received = new UnsafeBuffer(receiveBuffer);
    private final ByteBuffer sendBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH, 64);
    private final UnsafeBuffer sending = new UnsafeBuffer(sendBuffer);
    private final UnsafeBuffer commandBuffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH + 256]);

    private final RadiusPacket packet = new RadiusPacket();
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final AccountingResponses responses = new AccountingResponses(authenticator);
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private final AccountingAttributeExtractor extractor;
    private final AccountingFields fields = new AccountingFields();
    private final EventKeys keys = new EventKeys();
    private final DeviceIdentity device = new DeviceIdentity();
    private final ResponseCache cache = new ResponseCache();
    private final PendingTable pending;

    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final MessageHeaderDecoder headerDecoder = new MessageHeaderDecoder();
    private final AccountingCommandEncoder commandEncoder = new AccountingCommandEncoder();
    private final AccountingCommittedDecoder committedDecoder = new AccountingCommittedDecoder();
    private final AccountingRejectedDecoder rejectedDecoder = new AccountingRejectedDecoder();
    private final MessageHandler notificationHandler = this::onNotification;

    private final int[] delayed;
    private int delayedHead;
    private int delayedCount;

    private DatagramChannel channel;
    private long now;
    private long nextHousekeeping;

    /** Time source, replaceable in tests. */
    interface NanoClock {
        long nanoTime();
    }

    UdpAgent(
            GatewayConfig config,
            NasRegistry registry,
            VendorFormats vendorFormats,
            RingBuffer toCluster,
            RingBuffer fromCluster,
            GatewayStats stats,
            NanoClock clock) {
        this.config = config;
        this.registry = registry;
        this.toCluster = toCluster;
        this.fromCluster = fromCluster;
        this.stats = stats;
        this.clock = clock;
        this.extractor = new AccountingAttributeExtractor(vendorFormats);
        this.pending = new PendingTable(config.pendingCapacity());
        this.delayed = new int[Integer.highestOneBit(Math.max(1, config.pendingCapacity()) * 2)];
    }

    @Override
    public void onStart() {
        try {
            channel = DatagramChannel.open();
            channel.setOption(StandardSocketOptions.SO_RCVBUF, config.socketReceiveBuffer());
            channel.bind(new InetSocketAddress(config.listenHost(), config.listenPort()));
            channel.configureBlocking(false);
            stats.bound(true);
            LOG.info("listening for RADIUS accounting on {}", channel.getLocalAddress());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "cannot bind RADIUS socket " + config.listenHost() + ":" + config.listenPort(), e);
        }
    }

    /** Port actually bound (useful when configured as 0). */
    int localPort() {
        try {
            return ((InetSocketAddress) channel.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    @Override
    public int doWork() throws IOException {
        now = clock.nanoTime();
        int work = 0;
        for (int i = 0; i < RECEIVE_BATCH; i++) {
            receiveBuffer.clear();
            SocketAddress from = channel.receive(receiveBuffer);
            if (from == null) {
                break;
            }
            onDatagram((InetSocketAddress) from, receiveBuffer.position());
            work++;
        }
        work += fromCluster.read(notificationHandler, 256);
        work += sendDelayed();
        if (now - nextHousekeeping >= 0) {
            housekeeping();
            nextHousekeeping = now + HOUSEKEEPING_INTERVAL_NS;
        }
        return work;
    }

    // ---- receive path ------------------------------------------------------------------------------

    private void onDatagram(InetSocketAddress from, int length) {
        stats.increment(Counter.RECEIVED);
        if (packet.wrap(received, 0, length) != DecodeStatus.OK) {
            stats.increment(Counter.MALFORMED);
            return;
        }
        if (packet.code() != RadiusCode.ACCOUNTING_REQUEST) {
            stats.increment(Counter.NOT_ACCOUNTING);
            return;
        }
        NasClient nas = registry.lookup(from.getAddress());
        if (nas == null) {
            stats.increment(Counter.UNKNOWN_NAS);
            return;
        }
        byte[] secret = nas.secret();
        if (!authenticator.verifyAccountingRequest(packet, secret)) {
            stats.increment(Counter.AUTHENTICATOR_FAILED);
            return;
        }
        boolean hasMa = packet.hasMessageAuthenticator();
        NasClient.MessageAuthenticatorPolicy policy = nas.messageAuthenticator();
        if (policy != NasClient.MessageAuthenticatorPolicy.OFF
                && (hasMa || policy == NasClient.MessageAuthenticatorPolicy.REQUIRED)
                && (!hasMa || !authenticator.verifyRequestMessageAuthenticator(packet, secret))) {
            stats.increment(Counter.MESSAGE_AUTHENTICATOR_FAILED);
            return;
        }
        boolean respondWithMa = policy == NasClient.MessageAuthenticatorPolicy.REQUIRED
                || (policy == NasClient.MessageAuthenticatorPolicy.OPTIONAL && hasMa);

        int auth = packet.authenticatorOffset();
        long cacheKey = ResponseCache.key(
                from.getAddress().hashCode(),
                from.getPort(),
                packet.identifier(),
                received.getLong(auth),
                received.getLong(auth + 8));
        long cached = cache.get(cacheKey);
        if (ResponseCache.state(cached) == ResponseCache.COMMITTED) {
            stats.increment(Counter.CACHE_HITS);
            int responseLength = responses.encode(packet, sending, 0, secret, respondWithMa);
            send(from, responseLength);
            return;
        }
        if (ResponseCache.state(cached) == ResponseCache.PENDING) {
            int previous = pending.slotOf(ResponseCache.correlationId(cached));
            if (previous >= 0
                    && now - pending.createdAt(previous)
                            < config.resubmitAfter().toNanos()) {
                stats.increment(Counter.RETRANSMIT_IN_FLIGHT); // the original is still on its way
                return;
            }
            // pending for a while: the command may have been lost with a failed leader; submit it again,
            // the cluster's dedup makes that safe and a late commit of the old one is ignored
            if (previous >= 0) {
                pending.release(previous);
            }
            stats.increment(Counter.RESUBMITTED);
        }

        extractor.extract(packet, fields);
        if (!fields.has(AccountingFields.STATUS_TYPE)) {
            stats.increment(Counter.MALFORMED);
            return;
        }
        long statusType = fields.statusType();
        boolean hasSessionId = fields.has(AccountingFields.SESSION_ID);
        if (!hasSessionId && statusType <= 3) { // Start, Stop, Interim need Acct-Session-Id (RFC 2866 §5.5)
            stats.increment(Counter.MISSING_SESSION_ID);
            return;
        }
        long sessionTime = fields.has(AccountingFields.SESSION_TIME) ? fields.sessionTime() : 0;
        long eventTimestamp = fields.has(AccountingFields.EVENT_TIMESTAMP) ? fields.eventTimestamp() : 0;
        long inputOctets = octets64(AccountingFields.INPUT_OCTETS, AccountingFields.INPUT_GIGAWORDS, true);
        long outputOctets = octets64(AccountingFields.OUTPUT_OCTETS, AccountingFields.OUTPUT_GIGAWORDS, false);
        int presence = (fields.has(AccountingFields.SESSION_TIME) ? 1 : 0)
                | (fields.has(AccountingFields.EVENT_TIMESTAMP) ? 2 : 0);
        // devices behind one NAS entry (NAT): the identity attribute tells them apart (ADR 0019)
        int deviceLength = nas.identifiesDevices() ? device.resolve(nas, fields) : 0;
        boolean deviceUnknown = nas.identifiesDevices() && deviceLength == 0;
        if (deviceUnknown) {
            stats.increment(Counter.IDENTITY_MISSING);
        } else if (deviceLength > 0 && device.fallback()) {
            stats.increment(Counter.IDENTITY_FALLBACK);
        }
        keys.compute(
                nas.id(),
                device.buffer(),
                deviceLength,
                statusType,
                presence,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                fields.buffer(),
                hasSessionId ? fields.sessionIdOffset() : 0,
                hasSessionId ? fields.sessionIdLength() : 0);

        long correlationId = pending.allocate(cacheKey, now, from, nas, packet.identifier(), respondWithMa);
        if (correlationId < 0) {
            stats.increment(Counter.PENDING_FULL);
            return;
        }
        int slot = (int) correlationId;
        pending.authenticator(slot, received, auth);
        if (!copyProxyStates(slot)) {
            pending.release(slot);
            stats.increment(Counter.TOO_MANY_PROXY_STATES);
            return;
        }

        commandEncoder
                .wrapAndApplyHeader(commandBuffer, 0, headerEncoder)
                .correlationId(correlationId)
                .gatewayId(config.gatewayId())
                .nasId(keys.scope())
                .sessionKeyHi(keys.sessionHi())
                .sessionKeyLo(keys.sessionLo())
                .exactKeyHi(keys.exactHi())
                .exactKeyLo(keys.exactLo())
                .statusType(statusType)
                .sessionTime(sessionTime)
                .eventTimestamp(eventTimestamp)
                .inputOctets(inputOctets)
                .outputOctets(outputOctets)
                .nasClientId(nas.id())
                .identityFingerprint(nas.identityFingerprint())
                .idleTimeoutMinutes(nas.idleTimeoutMinutes())
                .userKey(
                        fields.has(AccountingFields.USER_NAME)
                                ? UserKeys.user(fields.buffer(), fields.userNameOffset(), fields.userNameLength())
                                : 0)
                .deviceKey(
                        fields.has(AccountingFields.CALLING_STATION_ID)
                                ? UserKeys.device(
                                        fields.buffer(),
                                        fields.callingStationIdOffset(),
                                        fields.callingStationIdLength())
                                : 0);
        commandEncoder
                .flags()
                .clear()
                .sessionTimePresent((presence & 1) != 0)
                .eventTimestampPresent((presence & 2) != 0)
                .sessionIdPresent(hasSessionId)
                .deviceUnknown(deviceUnknown);
        if (hasSessionId) {
            commandEncoder.putSessionId(fields.buffer(), fields.sessionIdOffset(), fields.sessionIdLength());
        } else {
            commandEncoder.putSessionId(received, 0, 0);
        }
        commandEncoder.putRawAttributes(
                received, packet.attributesOffset(), packet.length() - RadiusPacket.HEADER_LENGTH);
        commandEncoder.putNasDevice(device.buffer(), 0, deviceLength);
        int commandLength = MessageHeaderEncoder.ENCODED_LENGTH + commandEncoder.encodedLength();
        pending.command(slot, commandBuffer, 0, commandLength);
        if (!toCluster.write(COMMAND_MSG, commandBuffer, 0, commandLength)) {
            pending.release(slot);
            stats.increment(Counter.RING_FULL);
            return;
        }
        cache.put(
                cacheKey,
                ResponseCache.pending(correlationId),
                now + config.pendingTimeout().toNanos());
        stats.increment(Counter.SUBMITTED);
    }

    private long octets64(int octetsField, int gigawordsField, boolean input) {
        if (!fields.has(octetsField)) {
            return 0;
        }
        long octets = input ? fields.inputOctets() : fields.outputOctets();
        long giga = fields.has(gigawordsField) ? (input ? fields.inputGigawords() : fields.outputGigawords()) : 0;
        return ((giga & 0xFFFF_FFFFL) << 32) | (octets & 0xFFFF_FFFFL);
    }

    private boolean copyProxyStates(int slot) {
        int position = packet.attributesOffset();
        int end = packet.attributesEnd();
        while (position < end) {
            int attributeLength = received.getByte(position + 1) & 0xFF;
            if ((received.getByte(position) & 0xFF) == PROXY_STATE
                    && !pending.addProxyState(slot, received, position, attributeLength)) {
                return false;
            }
            position += attributeLength;
        }
        return true;
    }

    // ---- commit path -------------------------------------------------------------------------------

    private void onNotification(int msgTypeId, DirectBuffer buffer, int index, int length) {
        if (msgTypeId == NEW_LEADER_MSG) {
            resubmitPending();
            return;
        }
        headerDecoder.wrap(buffer, index);
        if (msgTypeId == COMMITTED_MSG) {
            committedDecoder.wrapAndApplyHeader(buffer, index, headerDecoder);
            int slot = pending.slotOf(committedDecoder.correlationId());
            if (slot < 0) {
                stats.increment(Counter.LATE_COMMITS);
                return;
            }
            switch (committedDecoder.outcome()) {
                case DUPLICATE -> stats.increment(Counter.DUPLICATES);
                case STALE -> stats.increment(Counter.STALE);
                default -> stats.increment(Counter.COMMITTED);
            }
            long delay = config.debugResponseDelay().toNanos();
            if (delay > 0) {
                pending.readyAt(slot, now + delay);
                delayed[(delayedHead + delayedCount++) & (delayed.length - 1)] = slot;
            } else {
                respond(slot);
            }
        } else if (msgTypeId == REJECTED_MSG) {
            rejectedDecoder.wrapAndApplyHeader(buffer, index, headerDecoder);
            int slot = pending.slotOf(rejectedDecoder.correlationId());
            stats.increment(Counter.REJECTED);
            if (slot >= 0) {
                cache.remove(pending.cacheKey(slot)); // stay silent; let the NAS retry later
                pending.release(slot);
            }
        }
    }

    /**
     * Commands offered to a leader that died before committing are gone; resubmit every pending one right away
     * instead of waiting for NAS retransmissions (Phase 2, P2.3). Duplicates of commands the old leader did
     * commit are answered as DUPLICATE by the cluster.
     */
    private void resubmitPending() {
        for (int slot = 0, n = pending.capacity(); slot < n; slot++) {
            if (!pending.inUse(slot) || pending.readyAt(slot) != 0) {
                continue; // free, or already committed and only waiting for the debug delay
            }
            int length = pending.commandLength(slot);
            if (length == 0) {
                continue; // too large to keep; the NAS retransmit will be resubmitted (ADR 0011)
            }
            if (toCluster.write(COMMAND_MSG, pending.commands(), pending.commandOffset(slot), length)) {
                stats.increment(Counter.RESUBMITTED_ON_NEW_LEADER);
            } else {
                stats.increment(Counter.RING_FULL);
                return;
            }
        }
    }

    private void respond(int slot) {
        NasClient nas = pending.nas(slot);
        encoder.wrap(sending, 0).header(RadiusCode.ACCOUNTING_RESPONSE, pending.identifier(slot));
        int proxyEnd = pending.proxyStateOffset(slot) + pending.proxyStateLength(slot);
        for (int p = pending.proxyStateOffset(slot); p < proxyEnd; ) {
            encoder.rawAttribute(pending.proxyStates(), p);
            p += pending.proxyStates().getByte(p + 1) & 0xFF;
        }
        int ma = pending.withMessageAuthenticator(slot) ? encoder.messageAuthenticator() : -1;
        int length = encoder.finish();
        authenticator.signResponse(sending, 0, length, ma, pending.authenticators(), slot * 16, nas.secret());
        send(pending.sender(slot), length);
        cache.put(
                pending.cacheKey(slot),
                ResponseCache.COMMITTED,
                now + config.responseCacheTtl().toNanos());
        pending.release(slot);
    }

    private int sendDelayed() {
        int sent = 0;
        while (delayedCount > 0) {
            int slot = delayed[delayedHead];
            if (!pending.inUse(slot)) {
                delayedHead = (delayedHead + 1) & (delayed.length - 1);
                delayedCount--;
                continue;
            }
            if (pending.readyAt(slot) - now > 0) {
                break;
            }
            delayedHead = (delayedHead + 1) & (delayed.length - 1);
            delayedCount--;
            respond(slot);
            sent++;
        }
        return sent;
    }

    private void send(InetSocketAddress to, int length) {
        sendBuffer.clear().limit(length);
        try {
            if (channel.send(sendBuffer, to) == length) {
                stats.increment(Counter.RESPONSES_SENT);
            } else {
                stats.increment(Counter.SEND_FAILED);
            }
        } catch (IOException e) {
            stats.increment(Counter.SEND_FAILED);
        }
    }

    // ---- housekeeping ------------------------------------------------------------------------------

    private void housekeeping() {
        long timeout = config.pendingTimeout().toNanos();
        for (int slot = 0, n = pending.capacity(); slot < n; slot++) {
            if (pending.inUse(slot) && pending.readyAt(slot) == 0 && now - pending.createdAt(slot) > timeout) {
                // no commit in time: forget it so the next NAS retransmit is submitted again
                if (ResponseCache.correlationId(cache.get(pending.cacheKey(slot))) == pendingCorrelation(slot)) {
                    cache.remove(pending.cacheKey(slot));
                }
                pending.release(slot);
                stats.increment(Counter.TIMED_OUT);
            }
        }
        cache.evict(now);
        stats.gauges(pending.size(), cache.size());
    }

    private long pendingCorrelation(int slot) {
        return pending.correlationId(slot);
    }

    @Override
    public void onClose() {
        stats.bound(false);
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException e) {
                LOG.warn("closing RADIUS socket failed", e);
            }
        }
    }

    @Override
    public String roleName() {
        return "radius-udp-" + config.gatewayId();
    }
}
