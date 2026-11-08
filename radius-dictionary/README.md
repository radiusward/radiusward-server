# radius-dictionary

Dictionary model and parser for FreeRADIUS-format RADIUS dictionaries.

- **Parser** (`DictionaryLoader`): the v3 syntax most operator installations use (`ATTRIBUTE`, `VALUE`,
  `VENDOR format=t,l[,c]`, `BEGIN-VENDOR`, `BEGIN-TLV`, `$INCLUDE`, `$INCLUDE-`, vendor name in the fifth
  column) and the v4 subset of the bundled FreeRADIUS master dictionaries (`BEGIN PROTOCOL`,
  `BEGIN <attr>`, `END-VENDOR <name>`, `ALIAS`, `MEMBER`, `DEFINE`, `FLAGS`, dotted and relative numbers).
- **Modes:** `STRICT` fails on anything unknown (used for the bundled set in tests); `LENIENT` skips with
  a warning naming file and line (used for operator files).
- **Layering:** sources load in order; later files extend or override earlier ones
  (`/etc/radiusward/dictionary.d/` after the bundled set). A compatible re-declaration becomes an alias,
  an incompatible one fails in strict mode and overrides with a warning in lenient mode.
- **Model:** an attribute tree as in FreeRADIUS v4 (`Vendor-Specific.Cisco.AVPair` = `26.9.1`).
  Number lookups (`attribute(int)`, `vendorAttribute(int, int)`, `vendor(int)`) are allocation-free
  and safe for the packet hot path; name lookups are for configuration and tooling.

```java
Dictionary dictionary = DictionaryLoader.builder()
        .addBundledFreeRadius(ParseMode.LENIENT)
        .addDirectory(Path.of("/etc/radiusward/dictionary.d"), ParseMode.LENIENT)
        .load();

AttributeDef avpair = dictionary.vendorAttribute(9, 1);        // Vendor-Specific.Cisco.AVPair
AttributeDef same   = dictionary.find("Cisco.AVPair");
long start          = dictionary.attribute(40).value("Start");  // 1
```

Dependencies: Agrona (primitive collections). See [docs/dictionaries.md](../docs/dictionaries.md).
