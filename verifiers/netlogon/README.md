# verifier-netlogon

Credential verifier for Active Directory over Netlogon (MS-NRPC), in pure Java — no Samba, no domain join on the
gateway hosts ([ADR 0025](../../docs/adr/0025-credential-verifiers-and-ldap.md)). **In progress** (work package 5.6b):

| Milestone | State |
|---|---|
| 1. DCE/RPC over TCP, endpoint mapper (`ept_map`) | done, tested against Samba AD |
| 2. Secure channel: `NetrServerReqChallenge`, `NetrServerAuthenticate3`, AES session key and credentials | done, tested against Samba AD |
| 3. Netlogon-signed and sealed RPC, `NetrLogonSamLogonEx` | next |
| 4. MS-CHAPv1/v2 and PAP, user session key for MPPE | |
| 5. Plug-in, DNS discovery of domain controllers, failover, metrics, `linux-tests` | |

The gateway authenticates as a workstation trust account that an administrator creates once (a computer object with
a known password).
