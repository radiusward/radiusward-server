/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * What a device logs in with over EAP: the method, the user and credential, and for the TLS-based methods the CAs it
 * trusts and its own certificate. {@link RadiusClient#eap} runs the conversation.
 *
 * <pre>{@code
 * EapLogin.peap("alice", "secret").trust(ca).outerIdentity("anonymous@example.org");   // inner MS-CHAPv2
 * EapLogin.ttls("alice", "secret").inner(EapLogin.Inner.PAP).trust(ca);
 * EapLogin.tls("alice@example.org", key, certificate).trust(ca);
 * EapLogin.md5("alice", "secret");
 * }</pre>
 */
public final class EapLogin {

    /** The outer method. */
    public enum Method {
        MD5,
        TLS,
        PEAP,
        TTLS
    }

    /** The method inside a PEAP or TTLS tunnel. */
    public enum Inner {
        /** PEAP and TTLS: MS-CHAPv2, the server's authenticator response checked. */
        MSCHAPV2,
        /** PEAP: EAP-GTC with the password. */
        GTC,
        /** TTLS: the password in a User-Password AVP. */
        PAP,
        /** TTLS: CHAP with the tunnel's implicit challenge. */
        CHAP,
        /** TTLS: MS-CHAPv1 with the tunnel's implicit challenge. */
        MSCHAP
    }

    final Method method;
    final String user;
    final String password;
    Inner inner;
    String outerIdentity;
    List<X509Certificate> trusted;
    boolean trustAny;
    PrivateKey key;
    X509Certificate[] chain;
    String tlsProtocol;
    int fragmentSize = 1000;

    private EapLogin(Method method, String user, String password) {
        this.method = method;
        this.user = user;
        this.password = password;
    }

    public static EapLogin md5(String user, String password) {
        return new EapLogin(Method.MD5, user, password);
    }

    /** PEAPv0, MS-CHAPv2 inside unless {@link #inner} says GTC. */
    public static EapLogin peap(String user, String password) {
        return new EapLogin(Method.PEAP, user, password).inner(Inner.MSCHAPV2);
    }

    /** EAP-TTLS, PAP inside unless {@link #inner} says otherwise. */
    public static EapLogin ttls(String user, String password) {
        return new EapLogin(Method.TTLS, user, password).inner(Inner.PAP);
    }

    /** EAP-TLS with a client certificate; {@code identity} is the EAP identity, matched against the certificate. */
    public static EapLogin tls(String identity, PrivateKey key, X509Certificate... chain) {
        EapLogin login = new EapLogin(Method.TLS, identity, null);
        login.key = key;
        login.chain = chain.clone();
        return login;
    }

    /** The method inside the tunnel. */
    public EapLogin inner(Inner inner) {
        boolean fits = method == Method.PEAP
                ? inner == Inner.MSCHAPV2 || inner == Inner.GTC
                : method == Method.TTLS && inner != Inner.GTC;
        if (!fits) {
            throw new IllegalArgumentException(inner + " is not an inner method of " + method);
        }
        this.inner = inner;
        return this;
    }

    /** The identity outside the tunnel (PEAP, TTLS), e.g. {@code anonymous@example.org}; default: the user. */
    public EapLogin outerIdentity(String identity) {
        this.outerIdentity = identity;
        return this;
    }

    /** The CAs the server's certificate must chain to (TLS-based methods). */
    public EapLogin trust(X509Certificate... cas) {
        this.trusted = List.of(cas);
        return this;
    }

    /** Accept any server certificate: only for experiments, a real device must check the server. */
    public EapLogin trustAnyServer() {
        this.trustAny = true;
        return this;
    }

    /** A client certificate for PEAP or TTLS too (EAP-TLS takes it in {@link #tls}). */
    public EapLogin clientCertificate(PrivateKey key, X509Certificate... chain) {
        this.key = key;
        this.chain = chain.clone();
        return this;
    }

    /** {@code TLSv1.2} or {@code TLSv1.3}; default: what both sides prefer. */
    public EapLogin tlsProtocol(String protocol) {
        this.tlsProtocol = protocol;
        return this;
    }

    /** The largest TLS fragment in one EAP packet (default 1000 bytes). */
    public EapLogin fragmentSize(int bytes) {
        if (bytes < 64 || bytes > 4000) {
            throw new IllegalArgumentException("fragment size 64 to 4000 bytes");
        }
        this.fragmentSize = bytes;
        return this;
    }

    public Method method() {
        return method;
    }

    String identity() {
        return outerIdentity != null && (method == Method.PEAP || method == Method.TTLS) ? outerIdentity : user;
    }

    boolean tlsBased() {
        return method == Method.TLS || method == Method.PEAP || method == Method.TTLS;
    }

    /** The TLS context: the trusted CAs (or any), and the client certificate if there is one. */
    SSLContext sslContext() {
        if (!trustAny && (trusted == null || trusted.isEmpty())) {
            throw new IllegalStateException(method + " needs trust(ca...) to check the server, or trustAnyServer()");
        }
        try {
            TrustManager[] trust;
            if (trustAny) {
                trust = new TrustManager[] {new AnyServer()};
            } else {
                KeyStore cas = KeyStore.getInstance("PKCS12");
                cas.load(null, null);
                for (int i = 0; i < trusted.size(); i++) {
                    cas.setCertificateEntry("ca-" + i, trusted.get(i));
                }
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(cas);
                trust = tmf.getTrustManagers();
            }
            javax.net.ssl.KeyManager[] keys = null;
            if (key != null) {
                char[] none = new char[0];
                KeyStore own = KeyStore.getInstance("PKCS12");
                own.load(null, null);
                own.setKeyEntry("client", key, none, chain);
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(own, none);
                keys = kmf.getKeyManagers();
            }
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keys, trust, new SecureRandom());
            return context;
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalStateException("cannot set up TLS: " + e.getMessage(), e);
        }
    }

    /** Trusts every server: for {@link #trustAnyServer()} only. */
    private static final class AnyServer implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // a client never checks clients
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // asked for explicitly: no check
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
