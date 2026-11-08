# Dictionaries

radiusward reads RADIUS dictionaries in the **FreeRADIUS format** and ships the FreeRADIUS dictionaries.

## What is bundled

`radius-dictionary-freeradius` contains `share/dictionary/radius` from FreeRADIUS **master**, pinned to
one commit (see [`SOURCE.properties`](../radius-dictionary-freeradius/src/main/resources/io/radiusward/radius/dictionary/freeradius/SOURCE.properties)):
249 files, ~7,200 attributes, ~190 vendors. Loading the whole set takes ~80 ms.

Why master and not v3.2.x: in v3.2.x `dictionary.meraki` has no CC BY 4.0 header; on master every
target vendor file has it. Master uses the v4 syntax, so the parser supports both (below).

Not loaded by default — exactly as in FreeRADIUS, the root `dictionary` does not `$INCLUDE` them:
`dictionary.ascend.illegal`, `dictionary.usr.illegal`, `dictionary.motorola.illegal`,
`dictionary.nokia.conflict`, `dictionary.huawei.v2`, `dictionary.cisco.vpn3000`, `dictionary.starent.vsa1`,
`dictionary.alcatel.esam`, `dictionary.altiga`, `dictionary.adva`, `dictionary.avaya`, `dictionary.openser`,
`dictionary.rfc5090`, `dictionary.alvarion.wimax.v2_2`, `dictionary.motorola.wimax`,
`dictionary.wimax.alvarion`, `dictionary.wimax.wichorus`. Operators who need one can `$INCLUDE` a copy from
`dictionary.d`.

## Licensing

The FreeRADIUS dictionaries are licensed **CC BY 4.0** (since 2022/2023; older copies were GPL). That
allows bundling them in an Apache-2.0 project with attribution:

- only files carrying the header `This work is licensed under CC-BY version 4.0` are bundled;
  currently `dictionary.ingate` is excluded for lacking it;
- the only modification is commenting out the excluded file's `$INCLUDE` in the root `dictionary`,
  recorded in that file's header;
- attribution: [NOTICE](../NOTICE), [THIRD-PARTY-LICENSES.md](../THIRD-PARTY-LICENSES.md), the README
  "Third-party resources" section, the full license text next to the files, and a
  "Derived from FreeRADIUS dictionaries (CC BY 4.0)" header in generated sources.

Decision record: [ADR 0008](adr/0008-dictionaries-licensing-codegen.md).

## Updating

```bash
scripts/update-dictionaries.sh <freeradius-server commit sha>
./mvnw verify   # strict-mode load of the whole set + fixture byte comparison
```

The script downloads that commit, copies every file with the CC BY 4.0 header, comments out `$INCLUDE`s
of excluded files, fails if any remaining `$INCLUDE` does not resolve, and writes `SOURCE.properties`.

## Operator dictionaries: `/etc/radiusward/dictionary.d/`

Files in this directory (non-hidden, regular files) are loaded in **name order after** the bundled set,
in lenient mode. Use them to add a vendor, fix an attribute, or include one of the not-loaded files.

| Situation | Result |
|---|---|
| new attribute or vendor | added |
| same number, same type, different name (typical v3 file, e.g. `Cisco-AVPair`) | the new name becomes an alias of the bundled attribute |
| same number, different type | overrides the bundled attribute, with a warning |
| unknown keyword, type or flag | line skipped, warning with file and line |
| directory missing | warning, startup continues |

Warnings are available from `Dictionary.warnings()` and will be logged at startup (Phase 1).

## Supported syntax

| Construct | v3 | v4 | Notes |
|---|---|---|---|
| `ATTRIBUTE name number type [flags] [vendor]` | ✓ | ✓ | v3 vendor name in the 5th column supported |
| `VALUE attribute name number` | ✓ | ✓ | forward references resolved at the end; hex numbers; IPv4 values |
| `VENDOR name id [format=t,l[,c]]` | ✓ | ✓ | |
| `BEGIN-VENDOR name [parent=… / format=Extended-Vendor-Specific-N]`, `END-VENDOR [name]` | ✓ | ✓ | |
| `$INCLUDE file`, `$INCLUDE- file` | ✓ | ✓ | relative to the including file; cycles detected |
| `BEGIN-TLV` / `END-TLV` | ✓ | | |
| `BEGIN PROTOCOL` / `BEGIN-PROTOCOL` … `END-PROTOCOL` | ✓ | ✓ | non-RADIUS protocols are skipped |
| dotted numbers `241.1`, relative numbers `.1` | ✓ | ✓ | relative = child of the last absolutely numbered tlv/struct/vsa |
| `BEGIN <attribute>` / `END <attribute>` | | ✓ | |
| `ALIAS name target` | | ✓ | |
| `MEMBER name type [flags]`, `struct`, `union`, `bit[n]` | | ✓ | parsed; members are addressable; not decoded on the wire yet |
| `DEFINE name type`, `FLAGS internal` | | ✓ | internal attributes never appear on the wire |
| types incl. v3 aliases (`integer`, `integer64`, `signed`, `extended`, `evs`, …) | ✓ | ✓ | |

Keywords and names are case-insensitive.

## Code generation

Constants and the hot-attribute extractor are generated from the dictionaries at build time — see
[radius-codegen](../radius-codegen/README.md). Generated code covers the bundled dictionaries; attributes
added through `dictionary.d` are decoded and named at runtime but have no generated accessors.
