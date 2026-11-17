/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.units;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PemTest {

    @TempDir
    Path dir;

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    /** Two certificates the JDK trusts, so the test needs no key material of its own. */
    private static List<Certificate> jdkCertificates() throws Exception {
        KeyStore cacerts = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of(System.getProperty("java.home"), "lib/security/cacerts"))) {
            cacerts.load(in, "changeit".toCharArray());
        }
        List<Certificate> two = new ArrayList<>();
        for (String alias : Collections.list(cacerts.aliases())) {
            if (two.size() < 2) {
                two.add(cacerts.getCertificate(alias));
            }
        }
        return two;
    }

    @Test
    void certificatesInTheirOrderAndATrustStoreOfThem() throws Exception {
        List<Certificate> two = jdkCertificates();
        Path bundle = Files.writeString(
                dir.resolve("ca.pem"),
                pem("CERTIFICATE", two.get(0).getEncoded()) + "# comment\n"
                        + pem("CERTIFICATE", two.get(1).getEncoded()));
        assertThat(List.<Certificate>copyOf(Pem.certificates(bundle))).containsExactlyElementsOf(two);
        assertThat(Pem.trustStore(bundle).size()).isEqualTo(2);
        assertThat(Pem.clientContext("TLS", null, null, bundle).getProtocol()).isEqualTo("TLS");
        Path empty = Files.writeString(dir.resolve("empty.pem"), "");
        assertThat(Pem.trustStore(empty).size()).isZero();
    }

    @Test
    void unencryptedPkcs8KeysOfEachAlgorithm() throws Exception {
        for (String algorithm : List.of("RSA", "EC", "Ed25519")) {
            PrivateKey key =
                    KeyPairGenerator.getInstance(algorithm).generateKeyPair().getPrivate();
            Path file = Files.writeString(dir.resolve(algorithm + ".key"), pem("PRIVATE KEY", key.getEncoded()));
            assertThat(Pem.privateKey(file).getEncoded()).as(algorithm).isEqualTo(key.getEncoded());
        }
    }

    @Test
    void otherKeyFormatsSayHowToConvert() throws Exception {
        Path traditional = Files.writeString(
                dir.resolve("rsa.key"), "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n");
        assertThatThrownBy(() -> Pem.privateKey(traditional))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("BEGIN PRIVATE KEY")
                .hasMessageContaining("openssl pkcs8 -topk8 -nocrypt");
        Path garbage = Files.writeString(
                dir.resolve("garbage.key"), pem("PRIVATE KEY", "not a key".getBytes(StandardCharsets.US_ASCII)));
        assertThatThrownBy(() -> Pem.privateKey(garbage)).hasMessageContaining("no RSA, EC or EdDSA key");
    }
}
