/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.ldap;

import io.radiusward.auth.StoreUnavailableException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.net.ssl.SSLSocketFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A directory reached with the JDK's LDAP client: a bounded pool of contexts bound as the service account for
 * searches, and fresh binds as a user to check a password. Contexts are not thread-safe, so each search borrows one;
 * waiting longer than {@code timeout} for a context, a connection or an answer makes the directory unavailable.
 */
final class Directory implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(Directory.class);

    /** One entry found by a search. */
    record Entry(String dn, Attributes attributes) {}

    private final LdapSettings settings;
    private final SSLSocketFactory tls;
    private final Semaphore permits;
    private final ArrayBlockingQueue<LdapContext> idle;
    private volatile boolean closed;

    Directory(LdapSettings settings) {
        this.settings = settings;
        this.tls = settings.tlsCa() == null ? null : TlsSocketFactory.trusting(settings.tlsCa());
        this.permits = new Semaphore(settings.pool());
        this.idle = new ArrayBlockingQueue<>(settings.pool());
    }

    private Hashtable<String, Object> environment(String principal, Object credentials) {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, settings.urls());
        env.put(Context.REFERRAL, "ignore");
        String millis = Long.toString(settings.timeout().toMillis());
        env.put("com.sun.jndi.ldap.connect.timeout", millis);
        env.put("com.sun.jndi.ldap.read.timeout", millis);
        env.put("com.sun.jndi.ldap.connect.pool", "false");
        if (tls != null) {
            env.put("java.naming.ldap.factory.socket", TlsSocketFactory.class.getName());
        }
        if (principal.isEmpty()) {
            env.put(Context.SECURITY_AUTHENTICATION, "none");
        } else {
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, principal);
            env.put(Context.SECURITY_CREDENTIALS, credentials);
        }
        return env;
    }

    private LdapContext open(String principal, Object credentials) throws NamingException {
        Hashtable<String, Object> env = environment(principal, credentials);
        return tls == null
                ? new InitialLdapContext(env, null)
                : TlsSocketFactory.use(tls, () -> new InitialLdapContext(env, null));
    }

    /** Searches below the base DN; {@code {0}…} in the filter are replaced by the escaped {@code args}. */
    List<Entry> search(String filter, Object[] args, String[] attributes, int limit) throws StoreUnavailableException {
        LdapContext context = borrow();
        boolean broken = true;
        try {
            SearchControls controls = new SearchControls(
                    SearchControls.SUBTREE_SCOPE,
                    limit,
                    (int) settings.timeout().toMillis(),
                    attributes,
                    false,
                    false);
            List<Entry> entries = new ArrayList<>();
            NamingEnumeration<SearchResult> results = context.search(settings.baseDn(), filter, args, controls);
            try {
                while (results.hasMore()) {
                    SearchResult r = results.next();
                    entries.add(new Entry(r.getNameInNamespace(), r.getAttributes()));
                }
            } catch (PartialResultException e) {
                // Active Directory ends a search below the domain with referrals, which are ignored
            } finally {
                results.close();
            }
            broken = false;
            return entries;
        } catch (javax.naming.SizeLimitExceededException e) {
            broken = false;
            throw new StoreUnavailableException("ldap store " + settings.name() + ": more than " + limit
                    + " entries match " + filter + " (user.filter must find one user)");
        } catch (NamingException e) {
            throw unavailable(e);
        } finally {
            release(context, broken);
        }
    }

    /**
     * Whether {@code password} is the password of the entry {@code dn}, by binding as it. An empty password is never
     * tried: many directories accept it as an anonymous bind.
     */
    boolean bind(String dn, byte[] password) throws StoreUnavailableException {
        if (password.length == 0) {
            return false;
        }
        try {
            if (!permits.tryAcquire(settings.timeout().toMillis(), TimeUnit.MILLISECONDS)) {
                throw new StoreUnavailableException("ldap store " + settings.name() + ": no connection free");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StoreUnavailableException("interrupted");
        }
        try {
            open(dn, password).close();
            return true;
        } catch (AuthenticationException e) {
            return false; // wrong password, disabled, expired or locked: the directory decides
        } catch (NamingException e) {
            throw unavailable(e);
        } finally {
            permits.release();
        }
    }

    private LdapContext borrow() throws StoreUnavailableException {
        if (closed) {
            throw new StoreUnavailableException("ldap store " + settings.name() + " closed");
        }
        try {
            if (!permits.tryAcquire(settings.timeout().toMillis(), TimeUnit.MILLISECONDS)) {
                throw new StoreUnavailableException("ldap store " + settings.name() + ": no connection free within "
                        + settings.timeout().toMillis() + " ms");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StoreUnavailableException("interrupted");
        }
        LdapContext context = idle.poll();
        if (context != null) {
            return context;
        }
        try {
            return open(settings.bindDn(), settings.bindPassword());
        } catch (AuthenticationException e) {
            permits.release();
            LOG.warn("ldap store {}: the service account cannot bind: {}", settings.name(), e.getMessage());
            throw new StoreUnavailableException("ldap store " + settings.name() + ": bind.dn rejected");
        } catch (NamingException e) {
            permits.release();
            throw unavailable(e);
        }
    }

    private void release(LdapContext context, boolean broken) {
        if (broken || closed || !idle.offer(context)) {
            closeQuietly(context);
        }
        permits.release();
    }

    private StoreUnavailableException unavailable(NamingException e) {
        String kind = e instanceof CommunicationException || e instanceof ServiceUnavailableException
                ? "unreachable"
                : "failed";
        return new StoreUnavailableException("ldap store " + settings.name() + " " + kind + ": "
                + e.getClass().getSimpleName() + " " + e.getMessage());
    }

    private static void closeQuietly(LdapContext context) {
        try {
            context.close();
        } catch (NamingException ignored) {
            // already broken
        }
    }

    @Override
    public void close() {
        closed = true;
        LdapContext c;
        while ((c = idle.poll()) != null) {
            closeQuietly(c);
        }
    }
}
