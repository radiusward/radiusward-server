/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

/**
 * EAP-TLS (RFC 5216, TLS 1.3: RFC 9190, ADR 0028): the client certificate is the credential. Success once the server's
 * last flight is acknowledged — for TLS 1.2 its Finished, for TLS 1.3 the one-byte commitment message after the
 * client's Finished.
 */
final class EapTls extends TlsTunnel {

    static final int TYPE = 13;
    static final int FLAG_LENGTH = TlsTunnel.FLAG_LENGTH;
    static final int FLAG_MORE = TlsTunnel.FLAG_MORE;
    static final int FLAG_START = TlsTunnel.FLAG_START;

    EapTls(EapTlsConfig config) {
        super(config);
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
        return Step.succeeded(msk());
    }

    @Override
    Step onData(byte[] data, Credentials credentials) {
        return Step.FAILED; // a peer has nothing to send inside EAP-TLS
    }
}
