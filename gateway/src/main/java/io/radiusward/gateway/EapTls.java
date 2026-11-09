/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.security.cert.X509Certificate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * EAP-TLS (RFC 5216, TLS 1.3: RFC 9190, ADR 0028): the client certificate is the credential. Success once the server's
 * last flight is acknowledged — for TLS 1.2 its Finished, for TLS 1.3 the one-byte commitment message after the
 * client's Finished.
 */
final class EapTls extends TlsTunnel {

    static final int TYPE = 13;
    private static final Logger LOG = LogManager.getLogger(EapTls.class);
    static final int FLAG_LENGTH = TlsTunnel.FLAG_LENGTH;
    static final int FLAG_MORE = TlsTunnel.FLAG_MORE;
    static final int FLAG_START = TlsTunnel.FLAG_START;

    private final String identity;
    private String authorized;

    /** @param identity the EAP identity the peer gave, checked against its certificate */
    EapTls(EapTlsConfig config, String identity) {
        super(config);
        this.identity = identity;
    }

    @Override
    public int type() {
        return TYPE;
    }

    @Override
    boolean clientCertificate() {
        return true;
    }

    @Override
    String keyLabel() {
        return "client EAP encryption";
    }

    @Override
    byte[] onFinished(boolean tls13) {
        return tls13 ? new byte[] {0} : null; // RFC 9190 §2.5: the commitment message
    }

    @Override
    Step onAck(Credentials credentials) {
        X509Certificate certificate = peerCertificate();
        if (certificate == null) {
            return Step.FAILED;
        }
        switch (config.identity()) {
            case MATCH -> {
                if (!CertificateIdentity.matches(certificate, identity)) {
                    LOG.debug("EAP-TLS identity {} is not a name of the certificate {}", identity, peer());
                    return Step.FAILED;
                }
            }
            case CERTIFICATE -> {
                authorized = CertificateIdentity.name(certificate);
                if (authorized == null) {
                    return Step.FAILED;
                }
            }
            case ANY -> {}
        }
        return Step.succeeded(msk());
    }

    /** With {@code auth.eap.tls.identity = certificate}: the certificate's name, authorized instead of the identity. */
    @Override
    public String innerIdentity() {
        return authorized;
    }

    @Override
    public boolean innerOptional() {
        return !config.requireUser();
    }

    @Override
    Step onData(byte[] data, Credentials credentials) {
        return Step.FAILED; // a peer has nothing to send inside EAP-TLS
    }
}
