# radius-codegen

Build-time generator that turns the dictionaries into Java. Runs in `radius-codec`'s
`generate-sources` phase (exec-maven-plugin); output goes to `target/generated-sources/radius` and is
never committed.

Generated into `io.radiusward.radius.codec.attributes`:

| Class | Content |
|---|---|
| `Ietf` | top-level attribute numbers and `VALUE` constants (`ACCT_STATUS_TYPE`, `ACCT_STATUS_TYPE_START`, ...) |
| `Cisco`, `Juniper`, `Unisphere` (Juniper ERX, 4874), `Mikrotik`, `Huawei`, `Meraki`, `Ruckus` | `VENDOR_ID`, vendor attribute numbers, values |
| `AccountingFields` | reusable holder for the hot attributes of one packet (primitives + offsets) |
| `AccountingAttributeExtractor` | one allocation-free pass over a packet that fills `AccountingFields` |

## Hot-attribute list

`radius-codec/src/main/codegen/hot-attributes.txt`:

```text
constants Cisco Juniper Unisphere Mikrotik ...   # vendors that get a constants class
ietf      Acct-Status-Type   statusType                 # vendor, attribute, Java field
Cisco     AVPair             ciscoAvPair   repeat=16    # repeated attributes keep up to N occurrences
```

Field kinds follow the dictionary type: integers/dates/IPv4 become `long` fields, everything else an
offset/length pair into the packet buffer. Every field has a presence bit (`has(AccountingFields.STATUS_TYPE)`);
values with the wrong length count as `malformedCount()`, ignored duplicates as `droppedCount()`.
Unknown attributes, duplicate fields or more than 64 fields fail the build with the spec line number.

Output is deterministic; files are rewritten only when their content changes.
