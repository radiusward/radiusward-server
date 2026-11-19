/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * A client certificate for EAP-TLS from the embedded server's throwaway CA: {@code EapLogin.tls(name, c.key(),
 * c.certificate())}.
 *
 * @param name its common name, the EAP identity that matches it
 */
public record ClientCertificate(String name, PrivateKey key, X509Certificate certificate) {}
