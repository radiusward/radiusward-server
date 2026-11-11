# Security policy

## Supported versions

Until the first release, fixes go to `main` and the `edge` image. After it, the latest release receives security
fixes; older releases are fixed only when a fix applies without an upgrade path change.

## Reporting a vulnerability

Please do not open a public issue. Report it privately with GitHub's
[Report a vulnerability](https://github.com/radiusward/radiusward-server/security/advisories/new) form on this
repository (Security → Advisories). Helpful to include: the affected version or commit, the configuration involved,
steps or packets to reproduce, and what an attacker gains.

- You get an answer within 7 days, and an assessment with a plan for a fix within 30 days.
- The fix is released before the advisory is published; we agree the disclosure date with you and credit you unless
  you prefer otherwise.

## In scope

Anything that lets an attacker bypass authentication or authorization, forge or replay accepted packets, read or
change accounting records or replicated state, lose acknowledged accounting records, crash or stall a gateway or a
member with crafted input, reach the management API without its token, or recover secrets or passwords.

## Out of scope

- Weaknesses of the RADIUS protocols themselves: MD5-based authenticators and attribute hiding (RFC 2865), DES in
  MS-CHAP (RFC 2433/2759), the MILENAGE functions of EAP-AKA. They are implemented as specified; the mitigations below
  apply.
- Findings that need a NAS shared secret, a management token or access to the hosts and their files.
- Denial of service by volume from an address the NAS registry accepts; gateways drop what they cannot handle rather
  than queue it.

## Running it securely

- **Message-Authenticator** (Blast-RADIUS, CVE-2024-3596): required on Access-Requests by default
  (`nas.<name>.access.message-authenticator=required`, always with EAP), and answers of home servers without it are
  ignored (`proxy.require.message-authenticator=true`). Relax it only for a NAS that cannot send it.
- **Transport:** RADIUS over UDP relies on the shared secret; use long random secrets, one per NAS, and keep UDP
  RADIUS on trusted networks. Where devices support it, use RadSec (TLS) or DTLS, which protect the whole packet.
- **Management port** (`/health`, `/ready`, `/state`, `/metrics`, the CoA and reload APIs): bound to `127.0.0.1` by
  default; the CoA and reload APIs exist only with a token (`coa.api.token`, `reload.api.token`, at least 16
  characters). Do not expose the port beyond the monitoring network.
- **Secrets** in properties files can come from the environment (`${env:NAS_SECRET}`), so they stay out of files and
  images; the Helm chart reads them from Kubernetes Secrets.
- **Stored passwords:** prefer bcrypt, SHA-crypt or yescrypt over cleartext; NT hashes and cleartext are needed only
  where the method requires them (MS-CHAP, CHAP).
- **Input handling:** malformed or unauthentic packets are silently discarded (RFC 2865 §3); the decoder is
  fuzz-tested, and container images are built with an SBOM and provenance.
