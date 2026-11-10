# ADR 0061: EAP-SIM, EAP-AKA and EAP-AKA′ with local SIM keys

Status: Accepted (2026-11-10). Work packages 5.37–5.41 ([plans/eap-sim-aka.md](../plans/eap-sim-aka.md)).

## Context
Devices of a private LTE/5G network join Wi-Fi with the keys on their SIM. RADIUS carries EAP-SIM (RFC 4186),
EAP-AKA (RFC 4187) and EAP-AKA′ (RFC 9048). Other servers' stable line offers EAP-SIM with COMP128 or stored
triplets; their development line all three methods with Milenage computed locally from stored keys, with SQN and
pseudonyms kept by site policy. The radio attach to the LTE/5G core is not RADIUS and not in scope.

## Decision
- **radiusward is the authentication centre**: vectors are computed from the subscriber's keys in an identity store
  (users file or SQL), under both naming schemes: `SIM-Ki`, `SIM-OPc`/`SIM-OP`, `SIM-AMF`, `SIM-SQN`,
  `SIM-Algo-Version` and `EAP-Sim-Ki`, `EAP-Sim-Algo-Version`, stored triplets `EAP-Sim-Rand1…3`/`SRES1…3`/`KC1…3`.
- **Algorithms**: MILENAGE (3GPP TS 35.206) and GSM-MILENAGE (conversions c2/c3 of TS 33.102) written from the
  specifications, checked against the TS 35.207/35.208 test sets; the FIPS 186-2 PRF (RFC 4186 Appendix B, SHA-1
  compression) checked against the FIPS example; AKA′'s CK′/IK′ (TS 33.402 Annex A) and PRF′. COMP128 v1–3 is not
  implemented (broken, 2G being switched off, only GPL implementations exist); such SIMs can use stored triplets.
- **SQN in the cluster** (5.38): one sequence number per subscriber, advanced by a replicated command so that every
  gateway and every failover sees the same value; resynchronisation from AUTS updates it.
- **Pseudonyms** are encrypted permanent identities (any gateway decrypts them, nothing stored); fast
  re-authentication state lives per gateway with a lifetime (5.41).

## Consequences
- Interoperability is tested with wpa_supplicant's `eapol_test` and its SIM/USIM simulator; EAP-SIM is also compared
  with the installed external server using stored triplets.
- Ki and OPc are as sensitive as passwords: never logged or traced.
