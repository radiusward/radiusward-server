/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.server.RadsecAgent.Counter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLongArray;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import org.agrona.concurrent.UnsafeBuffer;
import org.agrona.concurrent.ringbuffer.RingBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * What RadSec over TCP and RADIUS over DTLS do alike once a peer is connected (ADR 0034, ADR 0038): the NAS entry a
 * peer belongs to, by its address and certificate, and each RADIUS packet it sends to the agent that decides it.
 */
final class RadsecPeers {

    private static final Logger LOG = LogManager.getLogger(RadsecAgent.class);

    private final NasRegistry registry;
    private final RadsecLink link;
    private final boolean auth;

    /** @param auth whether Access-Requests are answered (otherwise only accounting) */
    RadsecPeers(NasRegistry registry, RadsecLink link, boolean auth) {
        this.registry = registry;
        this.link = link;
        this.auth = auth;
    }

    /** The handshake succeeded but the NAS may not use the transport: counted as such, not as a failed handshake. */
    static final class Refused extends IOException {
        Refused() {
            super("NAS refused");
        }
    }

    /**
     * The link index of the NAS entry a peer belongs to: the entry of its address if that allows the transport (and its
     * certificate carries the entry's identity, if one is set), else a certificate-only entry its certificate names.
     */
    int nasOf(
            SSLEngine engine,
            InetSocketAddress remote,
            Map<String, RadsecConfig.Client> clients,
            Map<String, Integer> indexes,
            List<NasClient> byCertificate,
            String transport,
            AtomicLongArray counters)
            throws Refused {
        X509Certificate certificate = peerCertificate(engine);
        NasClient nas = registry.lookup(remote.getAddress());
        Integer index = nas == null ? null : indexes.get(nas.name());
        RadsecConfig.Client client = index == null ? null : clients.get(nas.name());
        if (client == null && certificate != null) { // no entry for the address allows it: by certificate alone
            for (NasClient candidate : byCertificate) {
                if (CertificateIdentity.matches(
                        certificate, clients.get(candidate.name()).identity())) {
                    nas = candidate;
                    index = indexes.get(candidate.name());
                    client = clients.get(candidate.name());
                    break;
                }
            }
        }
        if (certificate == null
                || client == null
                || (client.identity() != null && !CertificateIdentity.matches(certificate, client.identity()))) {
            counters.incrementAndGet(Counter.NAS_REFUSED.ordinal());
            LOG.info(
                    "{} connection from {} refused: {}",
                    transport,
                    remote,
                    nas == null
                            ? "no NAS entry for the address"
                            : client == null
                                    ? "NAS entry " + nas.name() + " does not allow " + transport
                                    : "certificate " + certificate.getSubjectX500Principal() + " does not name "
                                            + client.identity());
            throw new Refused();
        }
        LOG.info("{} connection from {} for NAS {}", transport, remote, nas.name());
        return index;
    }

    private static X509Certificate peerCertificate(SSLEngine engine) {
        try {
            Certificate[] chain = engine.getSession().getPeerCertificates();
            return chain.length > 0 && chain[0] instanceof X509Certificate x ? x : null;
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }

    /**
     * A RADIUS packet from a NAS to the agent that decides it: Access-Requests to the {@link AuthAgent},
     * Accounting-Requests to the {@link UdpAgent}, Status-Server to the first of them, a CoA or Disconnect answer to the
     * {@link DynamicAuthorization} sender. A full ring drops it; the NAS retransmits.
     *
     * @param accountingPort a plain TCP accounting connection: Status-Server goes to accounting
     */
    void forward(
            long route,
            int nas,
            UnsafeBuffer packet,
            int code,
            int offset,
            int length,
            AtomicLongArray counters,
            boolean accountingPort) {
        if (code == DynamicAuthorization.DISCONNECT_ACK
                || code == DynamicAuthorization.DISCONNECT_NAK
                || code == DynamicAuthorization.COA_ACK
                || code == DynamicAuthorization.COA_NAK) {
            int index = link.fromNas.tryClaim(RadsecLink.PACKET_MSG, 4 + length);
            if (index > 0) {
                link.fromNas.buffer().putInt(index, nas);
                link.fromNas.buffer().putBytes(index + 4, packet, offset, length);
                link.fromNas.commit(index);
                counters.incrementAndGet(Counter.COA_ANSWERS.ordinal());
            } else {
                counters.incrementAndGet(Counter.DROPPED.ordinal());
            }
            return;
        }
        counters.incrementAndGet(Counter.REQUESTS.ordinal());
        RingBuffer ring = switch (code) {
            case RadiusCode.ACCESS_REQUEST -> auth ? link.toAuth : null;
            case RadiusCode.ACCOUNTING_REQUEST -> link.toAccounting;
            case RadiusCode.STATUS_SERVER -> auth && !accountingPort ? link.toAuth : link.toAccounting;
            default -> null;
        };
        if (ring == null) {
            counters.incrementAndGet(Counter.NOT_HANDLED.ordinal());
        } else if (!RadsecLink.request(ring, route, nas, packet, offset, length)) {
            counters.incrementAndGet(Counter.DROPPED.ordinal());
        }
    }
}
