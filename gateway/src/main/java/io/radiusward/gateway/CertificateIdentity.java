/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * How the EAP identity relates to the client certificate (ADR 0033): the names a certificate carries — the subject's
 * common name and the subject alternative names (e-mail, DNS, Microsoft UPN) — and whether an identity is one of them.
 * Windows machines authenticate as {@code host/<name>}, which matches a DNS name or a common name, also by its first
 * label.
 */
final class CertificateIdentity {

    /** {@code auth.eap.tls.identity}. */
    enum Check {
        /** The EAP identity must be one of the certificate's names; it is the user authorized. */
        MATCH,
        /** The EAP identity is ignored (it may be anonymous); the certificate's name is the user authorized. */
        CERTIFICATE,
        /** Any valid certificate, whatever the identity: only where the store has no per-user rules. */
        ANY
    }

    private static final int SAN_OTHER = 0;
    private static final int SAN_EMAIL = 1;
    private static final int SAN_DNS = 2;
    /** Microsoft User Principal Name, 1.3.6.1.4.1.311.20.2.3, DER encoded. */
    private static final byte[] UPN_OID = {0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, (byte) 0x82, 0x37, 0x14, 0x02, 0x03
    };

    private CertificateIdentity() {}

    /** Whether {@code identity} names this certificate (case-insensitive). */
    static boolean matches(X509Certificate certificate, String identity) {
        if (identity == null || identity.isEmpty()) {
            return false;
        }
        String id = identity.toLowerCase(Locale.ROOT);
        boolean host = id.startsWith("host/");
        String machine = host ? id.substring(5) : id;
        for (Name n : names(certificate)) {
            String value = n.value().toLowerCase(Locale.ROOT);
            if (!host && value.equals(id)) {
                return true;
            }
            if (host && (n.kind() == SAN_DNS || n.kind() == -1)) {
                int dot = value.indexOf('.');
                if (value.equals(machine)
                        || (machine.indexOf('.') < 0
                                && dot > 0
                                && value.substring(0, dot).equals(machine))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** The certificate's name for authorization: its UPN, else e-mail, else DNS name, else common name. */
    static String name(X509Certificate certificate) {
        List<Name> names = names(certificate);
        for (int kind : new int[] {SAN_OTHER, SAN_EMAIL, SAN_DNS, -1}) {
            for (Name n : names) {
                if (n.kind() == kind) {
                    return n.value();
                }
            }
        }
        return null;
    }

    /** @param kind the SAN type, -1 for the subject's common name */
    private record Name(int kind, String value) {}

    private static List<Name> names(X509Certificate certificate) {
        List<Name> names = new ArrayList<>();
        try {
            Collection<List<?>> san = certificate.getSubjectAlternativeNames();
            if (san != null) {
                for (List<?> entry : san) {
                    int kind = (Integer) entry.get(0);
                    Object value = entry.get(1);
                    if ((kind == SAN_EMAIL || kind == SAN_DNS) && value instanceof String s) {
                        names.add(new Name(kind, s));
                    } else if (kind == SAN_OTHER && value instanceof byte[] der) {
                        String upn = upn(der);
                        if (upn != null) {
                            names.add(new Name(SAN_OTHER, upn));
                        }
                    }
                }
            }
        } catch (CertificateParsingException e) {
            // no usable alternative names: the common name below
        }
        try {
            for (Rdn rdn : new LdapName(certificate.getSubjectX500Principal().getName()).getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    names.add(new Name(-1, rdn.getValue().toString()));
                }
            }
        } catch (InvalidNameException e) {
            // no common name
        }
        return names;
    }

    /**
     * The UTF8String of a UPN otherName (the JDK hands over its DER: [0] { OID, [0] { UTF8String } }), or {@code null}
     * for another otherName.
     */
    static String upn(byte[] der) {
        int at = indexOf(der, UPN_OID);
        if (at < 0) {
            return null;
        }
        for (int i = at + UPN_OID.length; i + 1 < der.length; i++) {
            if (der[i] == 0x0C) { // UTF8String
                int length = der[i + 1] & 0xFF;
                int start = i + 2;
                if (length > 0x7F) { // long form, one length byte is plenty for a name
                    if (length != 0x81 || start >= der.length) {
                        return null;
                    }
                    length = der[start] & 0xFF;
                    start++;
                }
                return start + length <= der.length ? new String(der, start, length, StandardCharsets.UTF_8) : null;
            }
        }
        return null;
    }

    private static int indexOf(byte[] data, byte[] part) {
        outer:
        for (int i = 0; i + part.length <= data.length; i++) {
            for (int j = 0; j < part.length; j++) {
                if (data[i + j] != part[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
