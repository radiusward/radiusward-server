# radiusward-bom

The versions of every published radiusward artifact, imported once, so the artifacts you use always match each
other. `radiusward-bom` pins only radiusward's own artifacts: it has no parent, so importing it does not change the
versions of JUnit, Aeron or any other library in your build.

**Stability:** Public API: kept compatible within a minor version (until 1.0, a minor version may change it, with a
note in the release).

## Use it

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.radiusward</groupId>
            <artifactId>radiusward-bom</artifactId>
            <version>0.1.0-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>io.radiusward</groupId>
        <artifactId>radiusward-junit</artifactId>     <!-- no version: it comes from the BOM -->
        <scope>test</scope>
    </dependency>
</dependencies>
```

Gradle: `testImplementation(platform("io.radiusward:radiusward-bom:0.1.0-SNAPSHOT"))`, then the artifacts without a
version.

## What's inside

| Artifacts | For |
|---|---|
| `radiusward-embedded`, `radiusward-junit`, `radiusward-client` | testing against radiusward in your JVM, and a RADIUS client with an EAP supplicant |
| `radiusward-auth-api`, `radiusward-export-api` | your own identity stores, credential verifiers and accounting sinks |
| the server, cluster, codec, stores, sinks and tools | the internals the public artifacts depend on (internal; may change in any release) |

## Requirements

None of its own. Releases and snapshots are on GitHub Packages, which asks for a token with `read:packages`
([release.md](../docs/operations/release.md#maven-artifacts)); Maven Central follows.

## Learn more

- [The main README: use it as a library](../README.md#use-it-as-a-library-development-and-tests)
- [testing/embedded-consumer](../testing/embedded-consumer): a project that imports it

## License

Apache-2.0.
