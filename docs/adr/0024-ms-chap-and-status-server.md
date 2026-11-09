# ADR 0024: MS-CHAP and Status-Server

Status: Accepted (2026-11-09). Phase 5, work package 5.6 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Windows clients, PPTP/L2TP VPNs and many routers authenticate with MS-CHAP; version 2 is also the inner method of
PEAP (5.8). MS-CHAP cannot be verified from a salted hash: it needs the NT hash (MD4 of the UTF-16LE password), which
is equivalent to the password for this protocol. NAS devices and load balancers probe servers with Status-Server
(RFC 5997) and mark a server down when it stays silent.

## Decision
- **MS-CHAPv2** (RFC 2759) and **MS-CHAPv1** (RFC 2433, NT response only; a LAN Manager-only response is rejected)
  are verified in the gateway workers like PAP and CHAP; check items, groups, reply items and `Simultaneous-Use`
  apply unchanged.
- **Credentials**: `NT-Password` (32 hex digits) works without opt-in; `Cleartext-Password` is used for MS-CHAP only
  where the store allows it (`auth.store.<name>.mschap = true`), like `chap` for CHAP. `NT-Password` also verifies PAP.
- **Success**: v2 answers `MS-CHAP2-Success` (the authenticator response, proving the server knew the password) and
  always `MS-MPPE-Send-Key`/`MS-MPPE-Recv-Key` (RFC 3079, encrypted per RFC 2548 with unique salts), since encrypted
  VPNs need them; v1 answers `MS-CHAP-MPPE-Keys` (no LAN Manager key, the NT key = MD4 of the NT hash). These method
  attributes are never removed by the vendor filter (ADR 0022). `MS-MPPE-Encryption-Policy`/`-Types` are reply items
  the operator adds.
- **Failure**: every MS-CHAP Reject carries `MS-CHAP-Error` with `E=691 R=0` (v2: also `C=` and `V=3`) — the generic
  authentication failure; the reason stays in the logs.
- **Cryptography** from the JDK (SHA-1, MD5, DES); MD4, which the JDK does not offer to applications, is our own small
  implementation checked against RFC 1320. All of it verified against the RFC 2759 and RFC 3079 vectors.
- **Status-Server** is answered on both ports, only with a valid Message-Authenticator, never cached and never sent to
  the cluster: on 1812 with an Access-Accept; on 1813 with an Accounting-Response only while the gateway is connected
  to the cluster, so a NAS fails over exactly when accounting could not be acknowledged.
- **Active Directory** (MS-CHAP without NT hashes in a store) comes as a separate package, 5.6b: a credential
  verifier talking Netlogon to the domain controllers.

## Consequences
- A store holding NT hashes must be protected like one holding passwords.
- MS-CHAPv1 is weaker than v2 and only there for old clients; it shares all code with v2.
- Status-Server lets load balancers and NAS devices see a gateway without its cluster as down.
