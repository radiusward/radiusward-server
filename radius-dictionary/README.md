# radiusward-dictionary

`radiusward-dictionary` parses RADIUS dictionary files into an attribute tree that the codec, the code generator and
the RADIUS server use to name, number and type attributes. It reads the bundled dictionaries
([radiusward-dictionaries](../radius-dictionary-freeradius/README.md)) and the operator's own files, layered in order.

**Stability:** Internal: published as a dependency of `radiusward-codec`, and with it of `radiusward-client`, `radiusward-export-api` and the radiusward server; it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward-codec` brings it, and through the codec `radiusward-client`,
`radiusward-export-api`, `radiusward-embedded` and the radiusward server do. Operators add dictionaries by dropping
files into `/etc/radiusward/dictionary.d/`, not through code.

## What's inside

| Type | Role |
|---|---|
| `DictionaryLoader` | loads sources in order: `builder()`, `addBundledFreeRadius(mode)`, `addDirectory(path, mode)`, `add(source, mode)`, `load()`; `loadBundled()` loads only the bundled set in strict mode |
| `DictionarySource` | a classpath resource or a file, resolving its `$INCLUDE` lines; `bundledFreeRadius()` is the bundled root dictionary |
| `ParseMode` | `STRICT` fails on anything unknown (the bundled set in tests); `LENIENT` skips it with a warning naming file and line (operator files) |
| `Dictionary` | the loaded, immutable tree; number lookups `attribute(int)`, `vendorAttribute(int, int)`, `vendor(int)` are allocation-free and safe on the packet hot path; name lookups `find(String)`, `require(String)` are for configuration and tooling; `warnings()`, `loadedFiles()` |
| `AttributeDef` | an attribute: name, number, `DataType`, parent, vendor, flags (tag, concat, encrypt, array), children, alternate names, named values (`value(String)`, `valueName(long)`), `path()` and `oid()` |
| `VendorDef` | a vendor: name, id and its VSA layout `format=t,l[,c]` (type length, length length, continuation) |
| `DataType` | the attribute data types, their wire lengths and dictionary names |
| `DictionaryException` | a dictionary that cannot be loaded (strict-mode problems, unreadable files) |

**Syntax.** The v3 syntax most installations use (`ATTRIBUTE`, `VALUE`, `VENDOR format=t,l[,c]`, `BEGIN-VENDOR`,
`BEGIN-TLV`, `$INCLUDE`, `$INCLUDE-`, a vendor name in the fifth column) and the v4 subset the bundled dictionaries use
(`BEGIN PROTOCOL`, `BEGIN <attr>`, `END-VENDOR <name>`, `ALIAS`, `MEMBER`, `DEFINE`, `FLAGS`, dotted and relative
numbers).

**Layering.** Sources load in the order they are added; later files extend or override earlier ones
(`/etc/radiusward/dictionary.d/` after the bundled set, its files in name order, hidden files skipped, a missing
directory ignored with a warning). A re-declaration with the same type becomes an alias; one with a different type
fails in strict mode and overrides with a warning in lenient mode.

**Model.** One attribute tree: `Vendor-Specific.Cisco.AVPair` is `26.9.1`.

## Example

```java
Dictionary dictionary = DictionaryLoader.builder()
        .addBundledFreeRadius(ParseMode.LENIENT)
        .addDirectory(Path.of("/etc/radiusward/dictionary.d"), ParseMode.LENIENT)
        .load();

AttributeDef avpair = dictionary.vendorAttribute(9, 1);        // Vendor-Specific.Cisco.AVPair
AttributeDef same   = dictionary.find("Cisco.AVPair");
long start          = dictionary.attribute(40).value("Start");  // 1
```

## Requirements

Java 25. Runtime dependency: Agrona (primitive collections, Apache-2.0). The bundled dictionary files come in the
separate `radiusward-dictionaries` artifact, which the modules that load them depend on.

## Learn more

- [Dictionaries](../docs/dictionaries.md): what is bundled, supported syntax, operator dictionaries, code generation
- [ADR 0008: dictionaries, licensing and code generation](../docs/adr/0008-dictionaries-licensing-codegen.md)
- [radiusward-dictionaries](../radius-dictionary-freeradius/README.md): the bundled files
- [radius-codegen](../radius-codegen/README.md): constants and the hot-attribute extractor generated from the dictionaries
- [radiusward-codec](../radius-codec/README.md): the packet codec that uses the tree

## License

Apache-2.0.
