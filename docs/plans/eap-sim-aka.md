# Plan: EAP-SIM, EAP-AKA and EAP-AKA′ with local SIM keys

Status: in progress (2026-11-10): 5.37 and 5.38 done. ADR [0061](../adr/0061-eap-sim-aka.md). Follows Phase 5 ([phase-5-auth.md](phase-5-auth.md)); work packages 5.37–5.41.

## Goal and scope

Devices with SIM cards — phones, tablets, routers and IoT modules of a **private LTE/5G network** — join **Wi-Fi**
with the keys already on their SIM: EAP-SIM (RFC 4186), EAP-AKA (RFC 4187) and EAP-AKA′ (RFC 9048, formerly 5448).
radiusward is the authentication centre (AuC) itself: it computes the vectors from subscriber keys kept in its
identity stores (users file or SQL), as other servers' current development line does.

The radio attach of the SIM to the LTE/5G network is **not** in scope: that is the core's job (MME/HSS over Diameter,
AUSF/UDM in 5G). Fetching vectors from a mobile operator's HLR/HSS (Sigtran MAP, Diameter SWx/Wx) is not in scope
either; it can follow later behind the same vector interface.

## Compatibility with other servers

| Area | 3.2 (stable) | 4.x (development) | radiusward |
|---|---|---|---|
| Methods | EAP-SIM | EAP-SIM, EAP-AKA, EAP-AKA′ | all three |
| Keys in the store | `EAP-Sim-Ki`, `EAP-Sim-Algo-Version` (COMP128 v1–3) | `SIM-Ki`, `SIM-OPc` or `SIM-OP`, `SIM-AMF`, `SIM-SQN`, `SIM-Algo-Version` (Comp128-1…4, Milenage) | both sets of names accepted as check items, so existing users files and `radcheck` rows work unchanged; algorithms Milenage and Comp128-4 (GSM-Milenage); a COMP128 v1–3 subscriber is rejected with a clear log line (not planned, see below) |
| Stored vectors | `EAP-Sim-Rand1…3`, `EAP-Sim-SRES1…3`, `EAP-Sim-KC1…3` | `RAND`/`SRES`/`KC`, `RAND`/`AUTN`/`XRES`/`CK`/`IK` from an AuC | stored triplets accepted (testing, migration); AuC quintuplets later |
| SQN | — | kept by policy (an SQL update), resync computes the new value into `SIM-SQN` | **kept in the cluster**: one value per subscriber shared by all gateways, failover-safe; the store's `SIM-SQN` is the starting floor |
| Pseudonyms, fast re-authentication | — | `Next-Pseudonym`, `Next-Reauth-Id`, stored by policy; 3GPP temporary-id encryption | pseudonyms encrypted with a shared key (no storage, any gateway resolves them); fast re-auth state per gateway with a lifetime |
| AKA′ network name | — | `network_name` / `KDF-Input` | `auth.eap.aka-prime.network.name`, per NAS entry if needed |

On the wire both servers follow the same RFCs, so devices see no difference; the algorithms are checked against the
3GPP and RFC test vectors, so both compute identical vectors and keys from the same Ki/OPc.

## Design

### Subscribers and identities
- The EAP identity is an NAI `<hint><IMSI>@wlan.mnc<MNC>.mcc<MCC>.3gppnetwork.org`: hint `1` SIM, `0` AKA, `6` AKA′
  for permanent identities; others for pseudonyms and re-authentication identities (RFC 4186/4187 §4.1, RFC 9048).
- The hint and realm are stripped and the IMSI looked up in the stores like a user name; groups, reply items,
  limits, pools, rules, CUI and the authentication log apply as for any user. The authorized user is the IMSI.
- Identity negotiation (`AT_PERMANENT_ID_REQ`, `AT_FULLAUTH_ID_REQ`, `AT_ANY_ID_REQ`) when the identity is unusable;
  `AT_CHECKCODE` protects it for AKA and AKA′.

### Vectors (`SimVectors`)
- **Milenage** (3GPP TS 35.206; OPc from OP when only `SIM-OP` is stored) → quintuplet RAND, XRES, CK, IK, AUTN for
  AKA/AKA′; **GSM-Milenage** (TS 55.205, "Comp128-4") folds it into triplets for EAP-SIM.
- **Stored triplets** (three, as 3.2 expects) for testing, migration and an odd legacy SIM; logged once as weak.
- AMF from `SIM-AMF` (default `0x8000` for AKA′, the separation bit; `0x0000` otherwise).

### Sequence numbers in the cluster
- New cluster command `SqnNext(subscriber key, floor)`: the state machine returns the next SQN, `max(current + 32,
  floor)` following TS 33.102 Annex C (SEQ‖IND with a 5-bit IND), and stores it. Deterministic, replicated, in the
  snapshot. **State version 8**, active with `atLeast(8)` once every member runs it (ADR 0005).
- Resync: on `AT_AUTS` the gateway verifies MAC-S, recovers SQN_MS with f5*, and sends `SqnResync(key, SQN_MS)`; one
  resync per conversation, then a new challenge.
- Like `Simultaneous-Use`, a gateway that cannot reach the cluster leaves the request unanswered.

### Keys and messages
- EAP-SIM and EAP-AKA: MK from SHA-1, keys from the FIPS 186-2 PRF (RFC 4186 §7, RFC 4187 §7); AT_MAC with
  HMAC-SHA1-128. EAP-AKA′: CK′/IK′ with the network name (TS 33.402 Annex A), PRF′ with HMAC-SHA-256, AT_KDF and
  AT_KDF_INPUT, AT_MAC with HMAC-SHA-256-128.
- MSK → MS-MPPE keys as for the other EAP methods; EMSK kept for later use.
- Notifications (failure codes 0, 1026, 1031, 16384, 32768), `Client-Error`, `Authentication-Reject`, protected result
  indication (`AT_RESULT_IND`, on by default as in 4.x), all through the existing EAP conversations (State,
  timeouts, limits).

### Identity privacy and fast re-authentication
- **Pseudonyms**: AES-encrypted IMSI with a key index (`auth.eap.sim.pseudonym.keys`, rotatable), sent in
  `AT_NEXT_PSEUDONYM` (encrypted in `AT_ENCR_DATA`); any gateway decrypts it, nothing stored.
- **Fast re-authentication**: `AT_NEXT_REAUTH_ID`; MK and counter kept per gateway for `auth.eap.sim.reauth.lifetime`
  with a maximum count; an unknown or expired one falls back to full authentication (no state in the cluster).

### Configuration (new keys)
`auth.eap.methods` gains `sim`, `aka`, `aka-prime`; `auth.eap.aka-prime.network.name`;
`auth.eap.sim.pseudonym.keys`; `auth.eap.sim.reauth.lifetime` / `.max`; `auth.eap.sim.result-indication`;
`auth.eap.sim.stored-triplets` (allow, default off); `auth.eap.sim.realm` (3GPP realm, else any realm accepted).

## Work packages

| # | Work package | Content | Size |
|---|---|---|---|
| 5.37 ✅ | Algorithms | Milenage f1–f5, f1*, f5* and OPc; GSM-Milenage; FIPS 186-2 PRF; TS 33.402 KDF and PRF′; all against the 3GPP and RFC test vectors | M |
| 5.38 ✅ | SQN in the cluster | `SqnNext`/`SqnResync` commands, state version 8, snapshot, rolling-upgrade gate, gateway client with a mailbox per worker | M |
| 5.39 | EAP-AKA and EAP-AKA′ | identities and hints, negotiation and checkcode, challenge, resync, notifications, result indication, keys; store attributes of both naming schemes | L |
| 5.40 | EAP-SIM | start/version negotiation, nonce, three triplets from GSM-Milenage or stored ones, keys | M |
| 5.41 | Privacy and fast re-auth | encrypted pseudonyms with key rotation, fast re-authentication with counters | M |

Each with an ADR, docs (`configuration.md`, the EAP section of the ADR index, strategy) and tests.

## Tests

- **Vectors**: Milenage test sets 1–6 (TS 35.207/35.208), GSM-Milenage (TS 55.205), FIPS 186-2 PRF (RFC 4186
  Appendix A), the RFC 4187 and RFC 9048 examples for keys, CK′/IK′ and AT_MAC.
- **Unit**: every message and attribute, malformed packets (status codes, no exceptions), identity negotiation,
  resync with a forged AUTS, replayed RAND, wrong MAC, expired State.
- **Cluster**: SQN determinism and snapshot/restore in `LocalCluster`, the version gate in `RollingUpgradeIT`,
  failover in the middle of an authentication.
- **Interop (`eapol_test`)**: the image is built with `CONFIG_SIM_SIMULATOR` and `CONFIG_USIM_SIMULATOR`, so a
  simulated SIM/USIM with a given Ki/OPc/SQN runs full authentication for all three methods, AKA′ with a network
  name, a resync (a SIM ahead of the server), pseudonym and fast re-authentication rounds.
- **Comparison with the installed 3.2**: EAP-SIM with the same stored triplets (computed with GSM-Milenage) on both
  servers gives the same MSK, like `ExternalEapComparisonIT` for PEAP and TEAP. 3.2 has no AKA; AKA and AKA′ are
  covered by the vectors and `eapol_test`.

## Not planned

- **COMP128 v1–3** (2G SIMs): v1 has been broken since 1998 (the Ki can be extracted from the card), v2/v3 were never
  officially published, 2G networks are being switched off, and SIMs issued for a private LTE/5G network are USIMs
  with Milenage. The known implementations are also GPL and could not be ported into this Apache-2.0 project. A legacy
  2G-only device can still use stored triplets.
- **TUAK** (3GPP TS 35.231, Keccak-based), the alternative to Milenage some newer SIMs use: rare today; added behind
  the same vector interface when a deployment asks for it.
- **Vectors from an operator's HLR/HSS** (Sigtran MAP, Diameter SWx/Wx) and IMSI encryption with an operator key:
  later, on request.

## Risks

- **Key protection**: Ki and OPc are as sensitive as passwords; they stay in the store (protect `radcheck` and the
  users file), are never logged or traced, and are zeroed after use.
- **Real devices**: Android and iOS EAP-SIM/AKA support depends on carrier configuration; tests with a programmable
  SIM (e.g. sysmoISIM) and a phone are worth doing before announcing it.
- **SQN under load**: one cluster command per full authentication; the existing reservation path handles that rate,
  measured in `LoadIT` before release.

## Order

5.37 → 5.38 → 5.39 (first usable: EAP-AKA′ and EAP-AKA) → 5.40 → 5.41. About the size of TEAP and EAP-pwd together,
plus the cluster work.
