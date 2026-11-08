# Security policy

radiusward processes RADIUS traffic, which is authenticated with MD5-based shared secrets.

- Report vulnerabilities privately via GitHub security advisories on this repository (or to the
  maintainers by email) — not in public issues. You will get an answer within 7 days.
- Deployment advice: keep RADIUS on trusted networks, use long random shared secrets per NAS, enable
  Message-Authenticator where NAS devices support it (Blast-RADIUS, CVE-2024-3596, mainly affects
  Access-Request; accounting verifies the Request Authenticator on every packet).
- Malformed or unauthentic packets are silently discarded; the decoder is fuzz-tested.
