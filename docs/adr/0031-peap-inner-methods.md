# ADR 0031: Inner methods of PEAP: EAP-GTC and EAP-TLS

Status: Accepted (2026-11-09). Phase 5, work package 5.8, milestone 4b ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
PEAP with EAP-MSCHAPv2 (ADR 0029) needs an NT hash or a domain controller. Sites with other password hashes or a
PAP-only directory (LDAP), and one-time-password systems, use EAP-GTC inside PEAP instead; Windows also offers
"smart card or other certificate", EAP-TLS inside PEAP.

## Decision
- `auth.eap.peap.inner` lists the inner methods PEAP offers, first preferred: `mschapv2` (default), `gtc`, `tls`. After
  the inner identity the first one starts; the peer may Nak to another listed one before it begins. A Nak that finds
  nothing, or a response of another type, ends with the Result TLV failure.
- **EAP-GTC** (type 6): the server sends a prompt, the peer answers with the password; it is checked like PAP — every
  stored format, or a credential verifier (LDAP bind, Netlogon). Success or failure is reported with the Result TLV.
  An outage keeps the conversation and repeats only the check on retransmission.
- **EAP-TLS inside** (type 13): a second TLS handshake in the tunnel, header-less, with a required client certificate
  checked against `auth.eap.tls.ca`. As with EAP-TLS outside, the inner identity needs no store entry unless
  `auth.eap.tls.require.user`; a store entry still applies. Keys come from the outer tunnel.
- The authorization after success is the inner user's, as for MS-CHAPv2.

## Consequences
- PEAP works against stores without NT hashes and against PAP-only directories.
- GTC carries the password in the clear inside TLS: the server certificate must be checked by the clients, as for TTLS.
- PEAPv1 remains out of scope; crypto-binding comes with milestone 5.
