# ADR 0056: Chargeable-User-Identity

Status: Accepted (2026-11-10). Phase 5, work package 5.32 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Roaming federations (eduroam, OpenRoaming) and visited operators need to tell sessions of the same user apart and bill
them without learning who the user is: tunnelled EAP hides the inner identity, and the outer one is often
`anonymous@realm`. RFC 4372 defines Chargeable-User-Identity (CUI): the NAS asks by sending the attribute with a
single NUL byte, the home server answers with a stable pseudonym.

## Decision
- With **`auth.cui.key`** (at least 16 characters) the gateway adds a CUI to Access-Accepts:
  `auth.cui.mode = requested` (default) when the request carries the attribute, `always` for every Accept.
- The value is HMAC-SHA-256(key, lower-case user name ‖ 0 ‖ Operator-Name), its first 16 bytes as 32 hex digits. The
  user is the authorized one: the inner user of PEAP, TTLS and TEAP. Different operators (Operator-Name, RFC 5580)
  get unrelated values for the same user; without Operator-Name the empty name is used.
- A CUI among the user's own reply items wins. Proxied requests carry the home server's CUI.
- The key can change with a reload; every CUI then changes, as with other servers.

## Consequences
- Accounting from the NAS carries the CUI it received; the cluster stores it like any attribute.
- Keep the key secret and stable: it is what keeps the pseudonyms unlinkable and constant.
