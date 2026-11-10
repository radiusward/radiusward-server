# ADR 0059: IPv6 prefix pools

Status: Accepted (2026-11-10). Phase 5, work package 5.35 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)). Extends
[ADR 0050](0050-ip-pools.md).

## Context
Broadband (BNG, PPPoE, IPoE) subscribers get a delegated prefix (DHCPv6-PD) and often a WAN prefix besides their IPv4
address; the BNG takes them from RADIUS (`Delegated-IPv6-Prefix`, `Framed-IPv6-Prefix`, RFC 4818 and 3162). Pools
were IPv4 only.

## Decision
- A pool is IPv6 with **`auth.pool.<name>.prefix`** (e.g. `2001:db8:100::/40`) and **`length`** (default 64): its
  entries are the prefixes of that length within it, at most 65 536. **`attribute`**: `Delegated-IPv6-Prefix`
  (default), `Framed-IPv6-Prefix`, or `Framed-IPv6-Address` (length 128, single addresses).
- The same table and allocation statement as IPv4 ([ADR 0050](0050-ip-pools.md)); the answer is returned in the
  pool's attribute (RFC 3162 encoding, which the codec now writes and reads).
- **Holding**: exported sessions show a framed IPv4 address, not a delegated prefix. An entry therefore also stays
  taken while **the device holding it** has an open exported session (same Calling-Station-Id), besides its lease;
  this rule applies to IPv4 entries too.
- **`Pool-Name`** may name several pools, comma-separated (`Pool-Name := "v4, pd"`): each fills its own attribute,
  unless the reply already has it.

## Consequences
- A device keeps its prefix across reconnects while it is online, and gets it back while the lease lasts.
- Devices without Calling-Station-Id are held by their user name and the lease alone.
