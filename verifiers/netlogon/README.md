# verifier-netlogon

Credential verifier for Active Directory over Netlogon (MS-NRPC), in pure Java — no Samba, no domain join on the
gateway hosts ([ADR 0025](../../docs/adr/0025-credential-verifiers-and-ldap.md)). **In progress** (work package 5.6b):

| Milestone | State |
|---|---|
| 1. DCE/RPC over TCP, endpoint mapper (`ept_map`) | done, tested against Samba AD |
| 2. Secure channel: `NetrServerReqChallenge`, `NetrServerAuthenticate3`, AES session key and credentials | done, tested against Samba AD |
| 3. Netlogon-signed and sealed RPC, `NetrLogonSamLogonEx` | done, tested against Samba AD |
| 4. The verifier: MS-CHAPv1/v2 and PAP, user session key for MPPE, channel pool, failover | done, tested against Samba AD, also through a real gateway |
| 5. DNS discovery of domain controllers, metrics, machine password rotation, `linux-tests` | next |

The gateway authenticates as a workstation trust account that an administrator creates once (a computer object with
a known password):

```powershell
New-ADComputer -Name RADIUSWARD -SamAccountName 'RADIUSWARD$' -Enabled $true
Set-ADAccountPassword -Identity 'RADIUSWARD$' -Reset -NewPassword (Read-Host -AsSecureString)
```

(Samba: `samba-tool computer create RADIUSWARD` and `samba-tool user setpassword 'RADIUSWARD$'`.)

```properties
auth.store.ad.verifier = dc            # users of the LDAP store are checked by the domain controller
auth.verifiers = dc
auth.verifier.dc.type = netlogon
auth.verifier.dc.server = dc1.corp.example dc2.corp.example
auth.verifier.dc.domain = CORP
auth.verifier.dc.machine.account = RADIUSWARD$
auth.verifier.dc.machine.password = ${env:NETLOGON_MACHINE_PASSWORD}
```

| Setting | Default | Meaning |
|---|---|---|
| `server` | — | domain controllers, tried in order |
| `domain` | — | NetBIOS domain name, for users given without one |
| `machine.account` / `machine.password` | — | the workstation trust account |
| `server.name` | the first server | the name given to the domain controller in calls |
| `endpoint.mapper.port` | `135` | where the Netlogon port is asked for |
| `netlogon.port` | asked | a fixed Netlogon port |
| `strip.realm` | `true` | `user@realm` is `user` in `domain` |
| `timeout` | `2s` | connect, call and channel wait |
| `connections` | `gateway.auth.workers` | secure channels kept open |

User names: `DOMAIN\user`, `user@realm` or `user`. MS-CHAPv1/v2 responses are forwarded; PAP becomes a network logon
(an NT response to a random challenge). Wrong passwords and disabled, locked or expired accounts are rejections; a
domain controller that cannot be reached, or a channel it no longer accepts, is retried once on a fresh channel
(the next server), then the request is not answered. The domain controller must allow MS-CHAPv2 logons
(Samba: `ntlm auth = mschapv2-and-ntlmv2-only`; Windows allows them with `MSV1_0_ALLOW_MSVCHAPV2`).

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

