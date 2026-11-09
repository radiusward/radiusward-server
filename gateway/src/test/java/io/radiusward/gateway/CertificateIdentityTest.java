/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The names of a client certificate and the EAP identities that match them (ADR 0033). */
class CertificateIdentityTest {

    @TempDir
    static Path dir;

    static TestPki pki;

    @BeforeAll
    static void certificates() throws Exception {
        pki = new TestPki(dir, "names");
    }

    @Test
    void commonNameOnly() throws Exception {
        X509Certificate c = pki.client("laptop-1").certificate();
        assertThat(CertificateIdentity.matches(c, "laptop-1")).isTrue();
        assertThat(CertificateIdentity.matches(c, "LAPTOP-1"))
                .as("case-insensitive")
                .isTrue();
        assertThat(CertificateIdentity.matches(c, "laptop-2")).isFalse();
        assertThat(CertificateIdentity.matches(c, "")).isFalse();
        assertThat(CertificateIdentity.matches(c, null)).isFalse();
        assertThat(CertificateIdentity.name(c)).isEqualTo("laptop-1");
    }

    @Test
    void alternativeNamesAndTheirPreference() throws Exception {
        X509Certificate c = pki.client(
                        "Alice Smith",
                        new GeneralName(GeneralName.rfc822Name, "alice.smith@corp.test"),
                        TestPki.upn("alice@corp.test"),
                        new GeneralName(GeneralName.dNSName, "alice-pc.corp.test"))
                .certificate();
        assertThat(CertificateIdentity.matches(c, "alice@corp.test")).as("UPN").isTrue();
        assertThat(CertificateIdentity.matches(c, "alice.smith@corp.test"))
                .as("e-mail")
                .isTrue();
        assertThat(CertificateIdentity.matches(c, "Alice Smith"))
                .as("common name")
                .isTrue();
        assertThat(CertificateIdentity.matches(c, "bob@corp.test")).isFalse();
        assertThat(CertificateIdentity.name(c)).as("the UPN first").isEqualTo("alice@corp.test");

        X509Certificate mail = pki.client("Bob", new GeneralName(GeneralName.rfc822Name, "bob@corp.test"))
                .certificate();
        assertThat(CertificateIdentity.name(mail)).isEqualTo("bob@corp.test");
    }

    @Test
    void windowsMachineIdentities() throws Exception {
        X509Certificate c = pki.client("PC-17", new GeneralName(GeneralName.dNSName, "pc-17.corp.test"))
                .certificate();
        assertThat(CertificateIdentity.matches(c, "host/pc-17.corp.test")).isTrue();
        assertThat(CertificateIdentity.matches(c, "host/PC-17"))
                .as("the short name")
                .isTrue();
        assertThat(CertificateIdentity.matches(c, "host/pc-18")).isFalse();
        assertThat(CertificateIdentity.matches(c, "pc-17.corp.test"))
                .as("a DNS name without host/")
                .isTrue();
        assertThat(CertificateIdentity.name(c)).isEqualTo("pc-17.corp.test");
    }

    @Test
    void otherNamesThatAreNoUpn() {
        assertThat(CertificateIdentity.upn(new byte[] {0x30, 0x03, 0x06, 0x01, 0x00}))
                .isNull();
        byte[] truncated = {
            0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, (byte) 0x82, 0x37, 0x14, 0x02, 0x03, 0x0C, 0x09, 'a'
        };
        assertThat(CertificateIdentity.upn(truncated)).isNull();
    }
}
