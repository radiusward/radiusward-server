/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.StoreUnavailableException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Checks MS-CHAPv1/v2 and PAP credentials against Active Directory over Netlogon ({@code auth.verifier.<name>.type =
 * netlogon}, ADR 0025): a bounded pool of secure channels, each authenticated with the workstation trust account, and
 * a network logon per request. PAP becomes a network logon too: an NT response to a random challenge.
 *
 * <p>Account problems (wrong password, disabled, locked, expired) are rejections; anything else — a domain controller
 * that cannot be reached, a channel it no longer accepts — is retried once on a fresh channel and then reported as
 * unavailable, never as an answer.
 */
final class NetlogonVerifier implements CredentialVerifier {

    private static final Logger LOG = LogManager.getLogger(NetlogonVerifier.class);

    /** Statuses that are an answer about the user, not about the channel. */
    static final Set<Long> REJECTIONS = Set.of(
            NetlogonException.STATUS_WRONG_PASSWORD,
            NetlogonException.STATUS_NO_SUCH_USER,
            NetlogonException.STATUS_LOGON_FAILURE,
            NetlogonException.STATUS_ACCOUNT_DISABLED,
            0xC000006EL, // STATUS_ACCOUNT_RESTRICTION
            0xC000006FL, // STATUS_INVALID_LOGON_HOURS
            0xC0000070L, // STATUS_INVALID_WORKSTATION
            0xC0000071L, // STATUS_PASSWORD_EXPIRED
            0xC0000193L, // STATUS_ACCOUNT_EXPIRED
            0xC0000224L, // STATUS_PASSWORD_MUST_CHANGE
            0xC0000234L, // STATUS_ACCOUNT_LOCKED_OUT
            0xC0000413L); // STATUS_AUTHENTICATION_FIREWALL_FAILED

    private final NetlogonSettings settings;
    private final byte[] machineNtHash;
    private final Semaphore permits;
    private final ArrayBlockingQueue<NetlogonClient> idle;
    private final ConcurrentHashMap<String, Integer> ports = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private volatile boolean closed;

    NetlogonVerifier(StoreContext context) {
        this.settings = NetlogonSettings.from(context);
        this.machineNtHash = NetlogonCrypto.ntHash(settings.machinePassword());
        this.permits = new Semaphore(settings.connections());
        this.idle = new ArrayBlockingQueue<>(settings.connections());
    }

    @Override
    public Result verifyMsChap(String userName, byte[] challenge, byte[] ntResponse, boolean v2)
            throws StoreUnavailableException {
        return logon(userName, challenge, ntResponse);
    }

    @Override
    public Result verifyPassword(String userName, byte[] password) throws StoreUnavailableException {
        String text = utf8(password);
        if (text == null || text.isEmpty()) {
            return Result.REJECTED;
        }
        byte[] challenge = new byte[8];
        random.nextBytes(challenge);
        byte[] ntHash = NetlogonCrypto.ntHash(text);
        try {
            Result r = logon(userName, challenge, NtResponse.of(challenge, ntHash));
            return r.accepted() ? Result.accepted(null) : r;
        } finally {
            Arrays.fill(ntHash, (byte) 0);
        }
    }

    private Result logon(String userName, byte[] challenge, byte[] ntResponse) throws StoreUnavailableException {
        String[] account = account(userName);
        IOException last = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            NetlogonClient client = borrow();
            boolean broken = true;
            try {
                NetlogonClient.Logon logon =
                        client.samLogon(settings.serverName(), account[0], account[1], challenge, ntResponse);
                broken = false;
                if (logon.status() == 0) {
                    return Result.accepted(logon.userSessionKey());
                }
                if (REJECTIONS.contains(logon.status())) {
                    return Result.REJECTED;
                }
                broken = true; // the channel is no longer good (e.g. the DC was restarted): try a fresh one
                last = new NetlogonException(logon.status(), "NetrLogonSamLogonEx");
            } catch (IOException e) {
                last = e;
            } finally {
                release(client, broken);
            }
        }
        throw new StoreUnavailableException(
                "netlogon verifier " + settings.name() + ": " + (last == null ? "no answer" : last.getMessage()));
    }

    /** {@code DOMAIN}&#92;{@code user}, {@code user@realm} (the default domain) or {@code user} (the default domain). */
    String[] account(String userName) {
        int slash = userName.indexOf('\\');
        if (slash > 0) {
            return new String[] {userName.substring(0, slash), userName.substring(slash + 1)};
        }
        int at = userName.lastIndexOf('@');
        if (at > 0 && settings.stripRealm()) {
            return new String[] {settings.domain(), userName.substring(0, at)};
        }
        return new String[] {settings.domain(), userName};
    }

    private NetlogonClient borrow() throws StoreUnavailableException {
        if (closed) {
            throw new StoreUnavailableException("netlogon verifier " + settings.name() + " closed");
        }
        try {
            if (!permits.tryAcquire(settings.timeout().toMillis(), TimeUnit.MILLISECONDS)) {
                throw new StoreUnavailableException("netlogon verifier " + settings.name() + ": no channel free");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StoreUnavailableException("interrupted");
        }
        NetlogonClient client = idle.poll();
        if (client != null) {
            return client;
        }
        try {
            return open();
        } catch (StoreUnavailableException e) {
            permits.release();
            throw e;
        }
    }

    /** A new secure channel to the first domain controller that accepts the machine account. */
    private NetlogonClient open() throws StoreUnavailableException {
        String reasons = "";
        for (String server : settings.servers()) {
            try {
                InetSocketAddress netlogon = new InetSocketAddress(server, port(server));
                NetlogonClient client = new NetlogonClient(netlogon, settings.timeout());
                try {
                    client.authenticate(
                            settings.serverName(), settings.machineAccount(), settings.machineName(), machineNtHash);
                    return client;
                } catch (IOException e) {
                    client.close();
                    throw e;
                }
            } catch (IOException e) {
                ports.remove(server); // the port may have changed with a restart
                reasons += " " + server + ": " + e.getMessage() + ";";
                LOG.debug("netlogon verifier {}: {} failed: {}", settings.name(), server, e.getMessage());
            }
        }
        throw new StoreUnavailableException("netlogon verifier " + settings.name() + ": no domain controller"
                + " accepted the secure channel:" + reasons);
    }

    private int port(String server) throws IOException {
        if (settings.netlogonPort() > 0) {
            return settings.netlogonPort();
        }
        Integer known = ports.get(server);
        if (known != null) {
            return known;
        }
        int port = EndpointMapper.port(
                new InetSocketAddress(server, settings.endpointMapperPort()),
                NetlogonClient.NETLOGON,
                1,
                0,
                settings.timeout());
        ports.put(server, port);
        return port;
    }

    private void release(NetlogonClient client, boolean broken) {
        if (broken || closed || !idle.offer(client)) {
            client.close();
        }
        permits.release();
    }

    private static String utf8(byte[] password) {
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(password))
                    .toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    List<String> servers() {
        return settings.servers();
    }

    @Override
    public void close() {
        closed = true;
        NetlogonClient c;
        while ((c = idle.poll()) != null) {
            c.close();
        }
    }
}
