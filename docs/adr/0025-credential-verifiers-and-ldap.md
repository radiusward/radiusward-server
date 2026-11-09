# ADR 0025: Credential verifiers, the LDAP store and Netlogon

Status: Accepted (2026-11-09). Phase 5, work package 5.6b ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Directories such as Active Directory do not give out passwords or NT hashes, so an identity store alone (ADR 0021)
cannot check a credential for their users: the directory itself, or a domain controller, has to. User data (groups,
attributes) still comes from the directory. MS-CHAP against AD needs Netlogon (MS-NRPC); the usual way is Samba's
winbind on a domain-joined host, which would add a native dependency and a domain join to every gateway.

## Decision
- **Credential verifiers**, a second plug-in type next to identity stores (`auth-api`: `CredentialVerifierProvider`,
  `CredentialVerifier`), loaded the same way. A verifier answers accepted (for MS-CHAP with the user session key,
  MD4 of the NT hash, from which the MS-CHAPv2 success message and the MPPE keys are derived), rejected, unsupported,
  or unavailable — never a guess. Configuration: `auth.verifiers`, `auth.verifier.<name>.*`; a user is checked by a
  verifier when `Auth-Type` names it, or when its store sets `auth.store.<name>.verifier` and the user has no password
  of its own. Check items, groups, reply items and `Simultaneous-Use` apply as for local users.
- **LDAP store** (`type = ldap`, JDK LDAP client, no new dependency): finds the user with `user.filter`, groups from
  `memberOf` or nested through Active Directory's in-chain rule, `require.groups`, group policies (`policy.<id>.*` in
  the users-file item syntax, now shared as `ItemParser`), attributes mapped to check and reply items, disabled and
  expired AD accounts rejected. LDAPS with an own CA (`tls.ca`); the JDK checks the server's host name. A bounded pool
  of service-account connections; timeouts and failover between the URLs.
- **LDAP verifier** (`type = ldap`): PAP by binding as the user; the directory applies its account rules. An empty
  password is never tried (it would be an anonymous bind).
- **Netlogon verifier** (`type = netlogon`): a pure-Java MS-NRPC client — DCE/RPC over TCP, the endpoint mapper, the AES
  secure channel with a workstation trust account, Netlogon-sealed RPC, `NetrLogonSamLogonEx` network logons for
  MS-CHAPv1/v2 and PAP — instead of Samba's winbind: no native dependency and no domain join on the gateway hosts;
  the machine account is created once by an administrator.
- **Tests** run against a Samba AD domain controller in a container (`testing/samba-ad`).

## Consequences
- AD sites combine the LDAP store (groups, attributes) with a verifier (LDAP bind for PAP, Netlogon for MS-CHAP).
- Pure Entra ID (formerly Azure AD) offers neither LDAP passwords nor Netlogon; certificate-based EAP-TLS (5.8) is the
  way there. Entra Domain Services and AD on Azure VMs behave like on-premises AD.
- The Netlogon client is tested against Samba; a check against a Windows domain controller is still due before it
  is called production-ready.
