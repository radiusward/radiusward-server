# radiusward-dictionaries

`radiusward-dictionaries` bundles the FreeRADIUS RADIUS dictionaries as classpath resources under
`io/radiusward/radius/dictionary/freeradius/`, so radiusward decodes the attributes of 190+ vendors without any files
on disk. It holds no code: [radiusward-dictionary](../radius-dictionary/README.md) parses the files, and the code
generator reads them at build time.

**Stability:** Internal: published as a dependency of `radiusward-export-api` and the radiusward server; it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward-export-api`, `radiusward-embedded` and the radiusward server
bring it. Load it with `DictionaryLoader.loadBundled()` or `DictionarySource.bundledFreeRadius()` from
`radiusward-dictionary`. Operators extend or override it with their own files in `/etc/radiusward/dictionary.d/`.

## What's inside

| Item | What it is |
|---|---|
| `dictionary` and `dictionary.*` | `share/dictionary/radius` of [freeradius-server](https://github.com/FreeRADIUS/freeradius-server) at one pinned commit: 249 files, ~7,200 attributes, ~190 vendors |
| [`SOURCE.properties`](src/main/resources/io/radiusward/radius/dictionary/freeradius/SOURCE.properties) | the source URL, commit, commit date, file count, excluded files and licence |
| `LICENSE-CC-BY-4.0.txt` | the full licence text, next to the files and at the [module root](LICENSE-CC-BY-4.0.txt) |

- **Only files carrying the CC BY 4.0 header** are bundled; `dictionary.ingate` is excluded for lacking it.
- **Unmodified**, except the root `dictionary`: the `$INCLUDE` of the excluded file is commented out and the change is
  recorded in its header.
- **Some files are bundled but not loaded:** the root `dictionary` does not `$INCLUDE` them (`*.illegal`, `*.conflict`,
  older vendor variants), exactly as in the FreeRADIUS source; an operator who needs one can `$INCLUDE` a copy from
  `dictionary.d` ([docs/dictionaries.md](../docs/dictionaries.md#what-is-bundled)).
- **Never edit by hand.** Refresh with `scripts/update-dictionaries.sh <commit-sha>`; the script fails if a file lacks
  the licence header or an `$INCLUDE` does not resolve, and rewrites `SOURCE.properties`.

## Requirements

No dependencies; resources only.

## Learn more

- [Dictionaries](../docs/dictionaries.md): what is bundled, licensing, updating, operator dictionaries
- [ADR 0008: dictionaries, licensing and code generation](../docs/adr/0008-dictionaries-licensing-codegen.md)
- [NOTICE](../NOTICE) and [THIRD-PARTY-LICENSES.md](../THIRD-PARTY-LICENSES.md)
- [radiusward-dictionary](../radius-dictionary/README.md): the parser

## License

Apache-2.0 for the module's build files. The bundled dictionary files are licensed CC BY 4.0
([LICENSE-CC-BY-4.0.txt](LICENSE-CC-BY-4.0.txt)), Copyright The FreeRADIUS Server project and contributors, and are
distributed unmodified apart from the one change recorded above.
