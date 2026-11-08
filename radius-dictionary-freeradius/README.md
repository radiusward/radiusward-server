# radius-dictionary-freeradius

The FreeRADIUS RADIUS dictionaries, bundled as classpath resources under
`io/radiusward/radius/dictionary/freeradius/`. No code.

- **Source:** `share/dictionary/radius` of [freeradius-server](https://github.com/FreeRADIUS/freeradius-server)
  at the commit in [`SOURCE.properties`](src/main/resources/io/radiusward/radius/dictionary/freeradius/SOURCE.properties).
- **License:** CC BY 4.0 ([LICENSE-CC-BY-4.0.txt](LICENSE-CC-BY-4.0.txt)), Copyright The FreeRADIUS Server
  project and contributors. Only files carrying the CC BY 4.0 header are bundled.
- **Unmodified**, except the root `dictionary`: the `$INCLUDE` of an excluded file is commented out and the
  change is recorded in its header.
- **Never edit by hand.** Refresh with `scripts/update-dictionaries.sh <commit-sha>`; the script fails if a
  file lacks the license header or an `$INCLUDE` does not resolve.

Load it with `DictionarySource.bundledFreeRadius()` or `DictionaryLoader.loadBundled()` from
`radius-dictionary`. A few files are bundled but not referenced by the root (`*.illegal`, `*.conflict`,
older vendor variants), exactly as in FreeRADIUS; see [docs/dictionaries.md](../docs/dictionaries.md).
