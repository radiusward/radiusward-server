# Samba AD test domain controller

A Samba Active Directory domain controller for the LDAP store and Netlogon tests — never for production. Built by
the tests (Testcontainers) from this directory when `ghcr.io/radiusward/radiusward-test-images:samba-ad-<hash>` is not
published ([test images](../../docs/testing/strategy.md#test-images)); runs privileged (Samba keeps ACLs in extended
attributes).

Domain `CORP.TEST` (NetBIOS `CORP`), provisioned at first start by `start.sh`:

| Account | Password | Notes |
|---|---|---|
| `alice` | `Alice-Passw0rd!` | VPN Users, Staff; through VPN Users also Remote Workers |
| `bob` | `Bob-Passw0rd!` | Staff |
| `carol` | `Carol-Passw0rd!` | disabled |
| `svc-radius` | `Svc-Passw0rd!` | service account for LDAP searches |
| `RADIUSWARD$` | `Machine-Passw0rd-1234567890` | workstation trust account for Netlogon |

`ntlm auth = mschapv2-and-ntlmv2-only`: MS-CHAPv2 logons (flagged as such) are allowed, MS-CHAPv1 and other NTLMv1
responses are not — as on hardened Windows domain controllers.

Ports: 389/636 (LDAP/LDAPS, simple binds need TLS), 135 (endpoint mapper), 49152–49155 (RPC, e.g. Netlogon).
