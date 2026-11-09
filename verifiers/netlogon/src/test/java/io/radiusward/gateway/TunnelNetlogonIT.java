/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import io.radiusward.verifier.netlogon.SambaAd;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * PEAP and TTLS whose inner credentials a domain controller checks: the gateway's EAP pipeline with users from the LDAP
 * store and the Netlogon verifier, against a Samba AD domain controller (Docker). The inner peers verify the server's
 * MS-CHAPv2 proof, which the gateway builds from the session key Netlogon returns.
 */
class TunnelNetlogonIT {

    static final String ALICE = "Alice-Passw0rd!";

    @TempDir
    static Path dir;

    static TestPki pki;
    static StoreAccessHandler handler;
    static final Dictionary DICTIONARY = DictionaryLoader.loadBundled();

    private final AccessContext context = new AccessContext();
    private final NasClient nas = AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
            .clients()
            .iterator()
            .next();

    @BeforeAll
    static void start() throws Exception {
        SambaAd.start();
        pki = new TestPki(dir, "ad");
        Map<String, String> c = new HashMap<>();
        c.put("auth.stores", "ad");
        c.put("auth.store.ad.type", "ldap");
        c.put("auth.store.ad.url", SambaAd.ldapsUrl());
        c.put("auth.store.ad.tls.ca", SambaAd.ca(dir).toString());
        c.put("auth.store.ad.bind.dn", "CN=svc-radius,CN=Users,DC=corp,DC=test");
        c.put("auth.store.ad.bind.password", "Svc-Passw0rd!");
        c.put("auth.store.ad.base.dn", "DC=corp,DC=test");
        c.put("auth.store.ad.verifier", "dc");
        c.put("auth.verifiers", "dc");
        c.put("auth.verifier.dc.type", "netlogon");
        c.put("auth.verifier.dc.server", SambaAd.endpointMapper().getHostString());
        c.put("auth.verifier.dc.server.name", "DC");
        c.put("auth.verifier.dc.netlogon.port", Integer.toString(SambaAd.netlogonPort()));
        c.put("auth.verifier.dc.domain", "CORP");
        c.put("auth.verifier.dc.machine.account", SambaAd.MACHINE_ACCOUNT);
        c.put("auth.verifier.dc.machine.password", SambaAd.MACHINE_PASSWORD);
        c.put("auth.plugins.dir", dir.resolve("plugins").toString());
        c.put("auth.eap.methods", "peap, ttls");
        c.put("auth.eap.peap.inner", "mschapv2, gtc");
        c.put("auth.eap.tls.certificate", pki.serverPem.toString());
        c.put("auth.eap.tls.key", pki.serverKey.toString());
        handler = new StoreAccessHandler(
                AuthStores.from(Config.of(c), 2, DICTIONARY), DICTIONARY, System::currentTimeMillis);
    }

    private RadiusPacket reply() {
        int length = context.replyAttributesLength();
        byte[] packet = new byte[RadiusPacket.HEADER_LENGTH + length];
        packet[0] = 2;
        packet[2] = (byte) (packet.length >> 8);
        packet[3] = (byte) packet.length;
        context.replyBuffer().getBytes(RadiusPacket.HEADER_LENGTH, packet, RadiusPacket.HEADER_LENGTH, length);
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(packet), 0, packet.length);
        return p;
    }

    private int handle(EapPacket eap, byte[] state) {
        byte[] request = StoreAccessHandlerTest.eapRequest(eap, state);
        context.reset(new UnsafeBuffer(request), 0, request.length, nas);
        return handler.handle(context);
    }

    /** A whole conversation of {@code type} with {@code client}; the first offered method is PEAP, TTLS by Nak. */
    private int converse(EapTlsClient client, int type) throws Exception {
        int code = handle(StoreAccessHandlerTest.identity(1, "anonymous@corp.test"), null);
        for (int rounds = 0; code == AccessHandler.CHALLENGE && rounds < 100; rounds++) {
            EapPacket request = EapPacket.from(reply());
            RadiusPacket r = reply();
            int at = r.findAttribute(24);
            byte[] state = new byte[(r.buffer().getByte(at + 1) & 0xFF) - 2];
            r.buffer().getBytes(at + 2, state);
            EapPacket response = request.type() == type
                    ? new EapPacket(EapPacket.RESPONSE, request.identifier(), type, client.answer(request.data()))
                    : new EapPacket(
                            EapPacket.RESPONSE, request.identifier(), EapPacket.TYPE_NAK, new byte[] {(byte) type});
            code = handle(response, state);
        }
        return code;
    }

    private EapTlsClient client(String protocol, java.util.function.UnaryOperator<byte[]> inner) throws Exception {
        return new EapTlsClient(TestPki.clientContext(null, pki.ca), protocol, 1024, inner);
    }

    @Test
    void peapMsChapV2AgainstTheDomainController() throws Exception {
        for (String protocol : List.of("TLSv1.3", "TLSv1.2")) {
            PeapPeer alice = new PeapPeer("alice", ALICE);
            assertThat(converse(client(protocol, alice), Peap.TYPE))
                    .as(protocol)
                    .isEqualTo(AccessHandler.ACCEPT);
            assertThat(alice.serverProved)
                    .as("S= from the session key Netlogon returned")
                    .isTrue();
        }
        PeapPeer wrong = new PeapPeer("alice", "wrong");
        assertThat(converse(client("TLSv1.3", wrong), Peap.TYPE)).isEqualTo(AccessHandler.REJECT);
        assertThat(wrong.failureSeen).isTrue();
        assertThat(converse(client("TLSv1.3", new PeapPeer("carol", "Carol-Passw0rd!")), Peap.TYPE))
                .as("disabled in the domain")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(converse(client("TLSv1.2", new PeapPeer("CORP\\alice", ALICE)), Peap.TYPE))
                .as("DOMAIN\\user inside the tunnel, as Windows sends it (strip.domain)")
                .isEqualTo(AccessHandler.ACCEPT);
    }

    @Test
    void ttlsMsChapV2AndPapAgainstTheDomainController() throws Exception {
        TtlsPeer msChap = new TtlsPeer("alice", ALICE, true, false);
        EapTlsClient c1 = client("TLSv1.3", msChap);
        msChap.client = c1;
        assertThat(converse(c1, Ttls.TYPE)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(msChap.serverProved).isTrue();

        TtlsPeer pap = new TtlsPeer("alice", ALICE, false, false);
        EapTlsClient c2 = client("TLSv1.2", pap);
        pap.client = c2;
        assertThat(converse(c2, Ttls.TYPE))
                .as("PAP as a Netlogon network logon")
                .isEqualTo(AccessHandler.ACCEPT);

        TtlsPeer wrong = new TtlsPeer("alice", "wrong", true, false);
        EapTlsClient c3 = client("TLSv1.2", wrong);
        wrong.client = c3;
        assertThat(converse(c3, Ttls.TYPE)).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void peapGtcAgainstTheDomainController() throws Exception {
        assertThat(converse(client("TLSv1.3", new PeapPeer("alice", ALICE, Peap.GTC, null)), Peap.TYPE))
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(converse(client("TLSv1.3", new PeapPeer("alice", "wrong", Peap.GTC, null)), Peap.TYPE))
                .isEqualTo(AccessHandler.REJECT);
    }
}
