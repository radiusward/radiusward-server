/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.ldap;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Trusts the CA certificates of {@code tls.ca} for {@code ldaps://} instead of the JDK's defaults. JNDI creates socket
 * factories through a static {@code getDefault()}, so the factory of the context being opened is handed over in a
 * thread-local around the call ({@link #use}). The JDK still checks the server's host name against its certificate.
 */
public final class TlsSocketFactory extends SSLSocketFactory {

    private static final ThreadLocal<SSLSocketFactory> CURRENT = new ThreadLocal<>();

    private final SSLSocketFactory delegate;

    private TlsSocketFactory(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

    /** Called by JNDI. */
    public static SocketFactory getDefault() {
        SSLSocketFactory current = CURRENT.get();
        return new TlsSocketFactory(current != null ? current : (SSLSocketFactory) SSLSocketFactory.getDefault());
    }

    /** A factory trusting the certificates in a PEM file. */
    static SSLSocketFactory trusting(Path pem) {
        try (InputStream in = Files.newInputStream(pem)) {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            int n = 0;
            for (Certificate c : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                store.setCertificateEntry("ca-" + n++, c);
            }
            if (n == 0) {
                throw new IllegalArgumentException("tls.ca: no certificate in " + pem);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(store);
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(null, tmf.getTrustManagers(), null);
            return ssl.getSocketFactory();
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException("tls.ca: cannot read " + pem + ": " + e.getMessage(), e);
        }
    }

    /** Runs {@code action} with {@code factory} as what {@link #getDefault()} hands out on this thread. */
    static <T, E extends Exception> T use(SSLSocketFactory factory, ThrowingSupplier<T, E> action) throws E {
        CURRENT.set(factory);
        try {
            return action.get();
        } finally {
            CURRENT.remove();
        }
    }

    @FunctionalInterface
    interface ThrowingSupplier<T, E extends Exception> {
        T get() throws E;
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegate.createSocket();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return delegate.createSocket(s, host, port, autoClose);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return delegate.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return delegate.createSocket(address, port, localAddress, localPort);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }
}
