# ADR 0032: PEAP crypto-binding and `eapol_test` interop

Status: Accepted (2026-11-09). Phase 5, work package 5.8, milestone 5 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
PEAP authenticates only the server in the tunnel; the inner MS-CHAPv2 exchange is not tied to it. A man in the middle
who gets a client to talk to a tunnel of their own can relay the inner exchange through a second tunnel to the real
server. MS-PEAP's crypto-binding closes this: both sides prove that the inner method and the tunnel belong together.
Windows, wpa_supplicant and Apple clients support it; wpa_supplicant can be told to require it (`crypto_binding=2`).

Our own test peers share our reading of the specifications, so they cannot find misreadings. An independent peer is
needed for every TLS method.

## Decision
- **Crypto-binding** (MS-PEAP §3.1.5.5, as wpa_supplicant implements it):
  - After a successful inner method, the Result TLV goes together with a Crypto-Binding TLV. The TLV holds a fresh
    nonce (last bit 0) and a compound MAC: HMAC-SHA1 with the CMK, over the TLV with a zero MAC, then the EAP type 25.
  - The keys are derived as follows:
    - IPMK and CMK = PRF+ (PEAPv0, HMAC-SHA1) over the first 40 bytes of the tunnel's keying material, with the label
      `Inner Methods Compound Keys` and the ISK.
    - ISK for EAP-MSCHAPv2: the server's receive key, then its send key (RFC 3079, 16 bytes each). ISK for inner
      EAP-TLS: its MSK. ISK for EAP-GTC: zeros.
  - The peer answers with a Crypto-Binding TLV of subtype response, our nonce, and its MAC.
    - MS-PEAP has the peer set the nonce's last bit; wpa_supplicant echoes the nonce unchanged. Both are accepted.
    - The subtype and the MAC already keep our own TLV from being reflected.
  - With a verified binding, the MSK, and with it the MS-MPPE keys, is the first 64 bytes of the compound session key:
    PRF+ over the IPMK, label `Session Key Generating Function` with a NUL byte. Without one, it is the tunnel's MSK.
  - `auth.eap.peap.crypto.binding` sets the policy:
    - `optional` (default): the TLV is sent. A peer may answer without one, because it does not support crypto-binding.
      An answer that does not verify fails.
    - `required`: the peer must answer the TLV.
    - `off`: no TLV is sent.
  - A failure Result TLV carries no binding. A peer that requires binding then ends the conversation itself.
- **Interop with `eapol_test`** (wpa_supplicant 2.10, Debian's `eapoltest`, image `testing/eapol-test`):
  - `EapolTestIT` runs it in a container against the real gateway over UDP.
  - It covers EAP-TLS, PEAP (MS-CHAPv2, GTC, inner EAP-TLS) and TTLS (PAP, MS-CHAPv2).
  - Each runs on TLS 1.2 and 1.3, with 400-byte fragments both ways.
  - PEAP runs with binding required and with binding off.
  - Negative cases: wrong passwords, a disabled user, a certificate of another CA, an identity that is not the
    certificate's.
  - Every Accept is checked by `eapol_test` itself: the MS-MPPE keys must equal its own MSK.
  - The container reaches the host as `host.docker.internal`. That is the bridge gateway on Linux and the host
    through Colima on macOS. Logs go to `gateway/target/eapol-test`.

## Consequences
- Relaying an inner MS-CHAPv2 exchange through another tunnel fails against binding-capable peers. With `required`, it
  fails for every peer, but peers without crypto-binding cannot connect.
- The key derivations of all three methods are checked against an implementation we did not write.
- The test needs Docker. Like the other Docker tests, it is skipped locally without Docker and fails in CI.
