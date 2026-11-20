# radiusward-verifier-netlogon

A built-in credential verifier that checks MS-CHAPv1/v2 and PAP credentials against Active Directory over Netlogon
(MS-NRPC), in pure Java: no Samba and no domain join on the RADIUS server hosts. It is what makes MS-CHAP (and PEAP
with inner MS-CHAPv2) work for directory users, which an LDAP bind cannot check. `radiusward-verifier-netlogon` is
enabled with `auth.verifier.<name>.type = netlogon`; operators set it up in a RADIUS server's settings, no code needed.

**Stability:** Internal: published as a dependency of the distribution (`radiusward.jar`); it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward.jar server` and the image have it. With
[`radiusward-embedded`](../../embedded/README.md), add it as a test dependency and enable it through `setting(...)`
with the keys below. To write a credential verifier of your own, use [`radiusward-auth-api`](../../auth-api/README.md).

## What's inside

| Type | Role |
|---|---|
| `NetlogonVerifierProvider`, `NetlogonVerifier` | the verifier (`type = netlogon`): a bounded pool of secure channels and a network logon per request; account problems are rejections, everything else is retried once on a fresh channel, then unavailable |
| `NetlogonSettings` | the settings (`auth.verifier.<name>.*`) |
| `DomainControllers` | the configured `server` list, or the DNS SRV records of `dns.domain`, looked up again every `dns.refresh` |
| `NetlogonClient`, `NetlogonCrypto` | the secure channel as a workstation trust account: `NetrServerReqChallenge`, `NetrServerAuthenticate3`, the AES session key and credentials |
| `NetlogonSecurity` | Netlogon-signed and sealed RPC (auth type 68, privacy level), as domain controllers require since the CVE-2020-1472 hardening |
| `RpcConnection`, `EndpointMapper`, `Ndr` | DCE/RPC over TCP, `ept_map` for the Netlogon port, the pieces of NDR Netlogon needs |
| `NtResponse` | the 24-byte NT response that turns a PAP password into a network logon |

| Milestone | State |
|---|---|
| 1. DCE/RPC over TCP, endpoint mapper (`ept_map`) | done, tested against Samba AD |
| 2. Secure channel: `NetrServerReqChallenge`, `NetrServerAuthenticate3`, AES session key and credentials | done, tested against Samba AD |
| 3. Netlogon-signed and sealed RPC, `NetrLogonSamLogonEx` | done, tested against Samba AD |
| 4. The verifier: MS-CHAPv1/v2 and PAP, user session key for MPPE, channel pool, failover | done, tested against Samba AD, also through a real RADIUS server |
| 5. DNS discovery of domain controllers, metrics, failover and outage tests | done |
| Check against a Windows domain controller | open — tested against Samba AD only |

**How it decides.** User names: `DOMAIN\user`, `user@realm` or `user`. MS-CHAPv1/v2 responses are forwarded; PAP
becomes a network logon (an NT response to a random challenge). Wrong passwords and disabled, locked or expired
accounts are rejections; a domain controller that cannot be reached, or a channel it no longer accepts, is retried
once on a fresh channel (the next server), then the request is not answered. The domain controller must allow
MS-CHAPv2 logons (Samba: `ntlm auth = mschapv2-and-ntlmv2-only`; Windows allows them with `MSV1_0_ALLOW_MSVCHAPV2`).

**Tunnels.** PEAP (inner MS-CHAPv2 or GTC) and TTLS (inner MS-CHAPv2 or PAP) use this verifier for their inner
credential; tested against Samba AD end to end (`TunnelNetlogonIT`).

**Outages.** Tested with a domain controller that does not answer (failover to the next one) and one frozen mid-way
(no answers meanwhile, a fresh channel afterwards, no RADIUS server restart).

**Metrics.** `radiusward_server_verifier_events_total{verifier,event}`: `accepted`, `rejected`, `unavailable`,
`channels_opened`, `server_failures`.

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

## Configuration

The RADIUS server authenticates as a workstation trust account that an administrator creates once (a computer
object with a known password):

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

Keys under `auth.verifier.<name>.`:

| Setting | Default | Meaning |
|---|---|---|
| `server` | — | domain controllers, space- or comma-separated, tried in order; without it they come from DNS |
| `dns.domain` | — | the domain's DNS name: domain controllers from the SRV records `_ldap._tcp.dc._msdcs.<dns.domain>` (lower priority first, then higher weight), as Windows clients find them |
| `dns.server` | the system's | a DNS server to ask (`host[:port]`) |
| `dns.refresh` | `10m` | how often the SRV records are looked up again (also after every domain controller failed) |
| `domain` | — (required) | NetBIOS domain name, for users given without one |
| `machine.account` / `machine.password` | — (required) | the workstation trust account |
| `server.name` | the first server (else `dns.domain`) | the name given to the domain controller in calls |
| `endpoint.mapper.port` | `135` | where the Netlogon port is asked for |
| `netlogon.port` | asked | a fixed Netlogon port |
| `strip.realm` | `true` | `user@realm` is `user` in `domain` |
| `timeout` | `2s` | connect, call and channel wait |
| `connections` | `server.auth.workers` | secure channels kept open |

A user reaches the verifier through a store's `auth.store.<name>.verifier`, or through `Auth-Type := <name>` in its
check items ([configuration.md](../../docs/configuration.md#identity-stores)).

**Machine password.** Domain controllers do not expire computer-account passwords; rotating them is the client's
choice. All RADIUS servers share the machine account, so one RADIUS server rotating it would lock the others out —
radiusward therefore does not rotate it. Rotate it by hand when your policy asks for it (`Set-ADAccountPassword`,
then update the secret on every RADIUS server), or give each RADIUS server its own machine account.

## Requirements

Java 25. No dependencies beyond `radiusward-auth-api` (which supplies MD4) and the Log4j 2 API (Apache-2.0): DCE/RPC, NDR and the
Netlogon cryptography are implemented here on the JDK. Tests run against a Samba AD domain controller in a container
([`testing/samba-ad`](../../testing/samba-ad/README.md)).

## Learn more

- [ADR 0025: credential verifiers and LDAP](../../docs/adr/0025-credential-verifiers-and-ldap.md),
  [ADR 0024: MS-CHAP and Status-Server](../../docs/adr/0024-ms-chap-and-status-server.md)
- [Configuration: identity stores](../../docs/configuration.md#identity-stores)
- [`radiusward-store-ldap`](../../stores/ldap/README.md), [`radiusward-auth-api`](../../auth-api/README.md),
  [`radiusward-server`](../../server/README.md)

## License

Apache-2.0.
