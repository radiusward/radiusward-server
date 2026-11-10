# ADR 0047: IPv6 NAS

Status: Accepted (2026-11-10). Phase 5, work package 5.23 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
NAS entries were IPv4 only: a packet from an IPv6 address matched no entry and was dropped. IPv6-only access networks
(mobile cores, new campus deployments) could not use the gateway at all.

## Decision
- **`nas.<name>.address` takes an IPv6 address or range** (`2001:db8::7`, `2001:db8:1::/48`). An address without a
  prefix is a /128. Only literals are accepted, as for IPv4.
- **`NasClient` keeps its IPv4 fields** and gains `network6` (16 bytes, `null` for IPv4); `singleAddress()` means /32
  or /128. Code that addresses a NAS (CoA) uses it instead of comparing the prefix with 32.
- **Lookup**:
  - IPv6 entries are scanned longest prefix first, after nothing else: IPv4 and IPv6 never overlap.
  - Getting an IPv6 address's bytes allocates in the JDK, so the last IPv6 sender's address object and its entry are
    remembered. The JDK hands out the same object for a sender that keeps sending, so a steady NAS costs no
    allocation.
  - The IPv4 path is unchanged, and `HotPathAllocationIT` still covers it.
- **Listening**: IPv6 needs `gateway.listen.host = ::` (dual stack; IPv4 NAS keep working) or an IPv6 address. The
  default `0.0.0.0` stays IPv4 only.
- **CoA**: a single-address IPv6 entry is sent to its address, and a session's NAS-IPv6-Address (95) is used like
  NAS-IP-Address. Requests carry NAS-IPv6-Address when the session named no NAS. The relay (ADR 0043) finds an entry
  by NAS-IPv6-Address too.
- **Not covered**: dynamic clients (ADR 0046) look up IPv4 addresses only. Sessions' event keys do not involve
  addresses, so nothing changes in the cluster.

## Tests
- `NasRegistryTest#ipv6EntriesMatchLongestPrefixFirst`: /128, /64 and /48 entries beside an IPv4 one, the cached
  repeat lookup, no IPv4 match for an IPv6 entry, bad prefixes and literals, duplicates.
- `Ipv6IT`: a gateway on `::` answers Access-Requests from `[::1]` with the IPv6 entry's secret (accept and reject),
  and its IPv4 NAS on the same socket. Skipped where the host has no IPv6 loopback.
