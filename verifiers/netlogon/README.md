# verifier-netlogon

Credential verifier for Active Directory over Netlogon (MS-NRPC), in pure Java — no Samba, no domain join on the
gateway hosts ([ADR 0025](../../docs/adr/0025-credential-verifiers-and-ldap.md)). **In progress** (work package 5.6b):

| Milestone | State |
|---|---|
| 1. DCE/RPC over TCP, endpoint mapper (`ept_map`) | done, tested against Samba AD |
| 2. Secure channel: `NetrServerReqChallenge`, `NetrServerAuthenticate3`, AES session key and credentials | done, tested against Samba AD |
| 3. Netlogon-signed and sealed RPC, `NetrLogonSamLogonEx` | done, tested against Samba AD |
| 4. MS-CHAPv1/v2 and PAP, user session key for MPPE | next |
| 5. Plug-in, DNS discovery of domain controllers, failover, metrics, `linux-tests` | |

The gateway authenticates as a workstation trust account that an administrator creates once (a computer object with
a known password).

Details that matter (each found against a real domain controller):

- The AES signature (auth type 68, privacy level) is 56 bytes, laid out as Windows sends it: algorithms, encrypted
  sequence number, the first 8 bytes of the HMAC-SHA256, the encrypted confounder, 24 zero bytes.
- One sequence number counts every message of the connection, requests and responses alike; the client's carry the
  top bit.
- The encrypted data and its checksum include the padding before the auth trailer.
- The user session key in the validation information is encrypted with the secure channel's session key (AES-CFB8,
  zero IV), even inside the sealed call.
- MS-CHAPv2 logons carry `MSV1_0_ALLOW_MSVCHAPV2`, so domain controllers that refuse NTLMv1 (Samba's default
  `ntlmv2-only`, hardened Windows) still accept them when configured to (`mschapv2-and-ntlmv2-only`).

