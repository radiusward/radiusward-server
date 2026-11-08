# ADR 0008: Bundled CC BY 4.0 FreeRADIUS dictionaries + code generation

Status: Accepted (2026-11-07). Supersedes the earlier plan to write our own RFC dictionary.

## Context
Operators know the FreeRADIUS dictionary format and vendor coverage matters. The FreeRADIUS server is
GPL, which would conflict with Apache-2.0 if the dictionaries were GPL too. They are not: since
2022/2023 the dictionary files are CC BY 4.0 (aaa4j-radius and toughradius bundle them the same way).

## Decision
- Bundle the FreeRADIUS `share/dictionary/radius` files from **master at a pinned commit** — the v3.2.x
  copy of `dictionary.meraki` lacks the CC BY 4.0 header.
- Only files with the CC BY 4.0 header; `scripts/update-dictionaries.sh` enforces it. Attribution in
  NOTICE, THIRD-PARTY-LICENSES.md, README, the license text next to the files, and generated sources.
- Parser supports v3 and the v4 subset; strict mode for the bundled set, lenient for operator files in
  `/etc/radiusward/dictionary.d/` (loaded after, can extend or override).
- **Code generation** at build time: constants per vendor and an allocation-free
  `AccountingAttributeExtractor` for the hot attributes listed in `hot-attributes.txt`; the runtime
  dictionary covers everything else.
- Target vendors with generated accessors and fixtures: Cisco, Juniper (Junos 2636 and ERX 4874 — named
  `Unisphere` in the dictionary, used by MX subscriber management), MikroTik, Huawei, Meraki, Ruckus.

## Consequences
- 190+ vendors decoded out of the box; Apache-2.0 stays (GPL relicensing rejected: Aeron/Agrona are
  Apache-2.0, incompatible with GPLv2).
- Dictionary updates are a scripted, reviewed change verified by the strict load and fixture tests.
- Juniper MX subscriber management sends ERX/Unisphere (vendor 4874) attributes; 12 of them (virtual
  router, PPPoE/interface description, DHCP MAC, service session, Acct-Request-Reason, gigapackets, IPv6
  octet counters + gigawords) are in the hot list since 2026-11-08.
