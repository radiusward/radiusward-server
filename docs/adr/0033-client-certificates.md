# ADR 0033: Client certificates: identity, revocation, reload

Status: Accepted (2026-11-09). Phase 5, work package 5.8, milestone 5 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
EAP-TLS (ADR 0028) accepted any certificate that chains to `auth.eap.tls.ca`, then authorized the EAP identity the
peer sent. A device with a valid certificate could therefore claim another user's identity and get that user's reply
items. Certificates are also revoked (stolen laptops, people who leave) and renewed. A renewal must not need a restart
of every gateway.

## Decision
- **Identity versus certificate** (`auth.eap.tls.identity`), for EAP-TLS and EAP-TLS inside PEAP:
  - `match` (default): the identity must be one of the certificate's names, compared case-insensitively. The names
    are the subject's common name and the subject alternative names e-mail, DNS and the Microsoft UPN (otherName
    1.3.6.1.4.1.311.20.2.3). Windows machines send `host/<name>`, which matches a DNS name or the common name, also
    by its first label.
  - `certificate`: the identity is ignored, so it may be anonymous, as RFC 9190 suggests for TLS 1.3. The user
    authorized is the certificate's name: UPN, else e-mail, else DNS name, else common name. The store entry is
    looked up by that name, and an anonymous outer identity needs none.
  - `any`: the previous behaviour, for stores without per-user rules only.
- **Revocation** (`auth.eap.tls.revocation`), with the JDK's PKIX revocation checker in the trust manager:
  - `none` (default).
  - `crl`: CRL files from `auth.eap.tls.crl`. Every certificate of the client's chain below the trust anchor needs
    its issuer's current CRL, otherwise the status is unknown and the handshake fails.
  - `ocsp`: the certificate's OCSP responder, or `auth.eap.tls.ocsp.url` for every certificate. Configured CRLs are a
    fallback. `auth.eap.tls.ocsp.timeout` (default 2 s) sets the JDK's connect and read timeouts, unless they are set
    as system properties. The request runs on the access worker, like a store lookup.
  - `auth.eap.tls.revocation.soft.fail`: an unknown status, such as a missing CRL or an unreachable responder,
    passes. A certificate known to be revoked still fails.
- **Reload**: the certificate, key, CA and CRL files are checked for changes (time and size) every
  `auth.eap.tls.reload` (default 60 s, `0s` = never). The check runs on the worker that starts a handshake.
  - A change builds a new TLS context for new conversations. Running ones keep their engine.
  - A change that does not load keeps the previous context and is retried at the next check. Examples: a certificate
    without its new key (the key is checked against the certificate at start and at every reload), or a half-written
    file.
  - `radiusward_gateway_eap_tls_reloads_total{result="loaded|failed"}` counts both outcomes.

## Consequences
- A certificate authenticates its own names only. Deployments whose devices send other identities choose
  `certificate` or, knowingly, `any`.
- CRLs must be refreshed before their next-update time. With `crl` an expired list fails every handshake of that CA;
  the reload picks up a refreshed file without a restart.
- An unreachable OCSP responder delays the handshakes that need it by up to the timeout and fails them, unless soft
  fail is on.
