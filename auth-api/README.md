# radiusward-auth-api

The interfaces for plugging your own user directory into radiusward: identity stores that look users up (their
password or hash, check items, groups and reply attributes) and credential verifiers that check a password somewhere
else, as an LDAP bind or a domain controller does. `radiusward-auth-api` is what a store plug-in compiles against,
and what a test passes to [radiusward-embedded](../embedded/README.md); the same class works in both.

**Stability:** Public API: kept compatible within a minor version (until 1.0, a minor version may change it, with a
note in the release).

## Use it

```xml
<dependency>
    <groupId>io.radiusward</groupId>
    <artifactId>radiusward-auth-api</artifactId>
    <!-- version from radiusward-bom; see the main README -->
    <scope>provided</scope> <!-- for a plug-in jar: the server brings it; for tests, test scope -->
</dependency>
```

Gradle: `compileOnly("io.radiusward:radiusward-auth-api")` for a plug-in (version from the BOM platform).

## What's inside

| Type | Role |
|---|---|
| `IdentityStore` | `lookup(userName)`: the user, empty if unknown, `StoreUnavailableException` if it cannot tell now (the request is then left unanswered, so an outage never becomes an Accept or a Reject); called from several worker threads at once |
| `IdentityStoreProvider` | `type()` (what `auth.store.<name>.type` names) and `create(StoreContext)`; settings errors as `IllegalArgumentException`; `IdentityStoreProvider.of(type, factory)` makes one in code |
| `StoreContext` | the store's name, its `auth.store.<name>.*` settings, the number of worker threads (size pools to it) |
| `UserRecord`, `AttributeItem` | check items, reply items and groups, each as attribute name, operator and text value |
| `CredentialVerifier`, `CredentialVerifierProvider` | check a PAP password or an MS-CHAP response elsewhere for users whose store holds no password ([ADR 0025](../docs/adr/0025-credential-verifiers-and-ldap.md)); `ACCEPTED`, `REJECTED` or `UNSUPPORTED` |
| `ItemParser` | reads items in the users-file syntax (`Class := gold, Session-Timeout = 3600`) |

Stores hold no RADIUS logic: the RADIUS server verifies passwords (cleartext, hashes, CHAP, MS-CHAP, EAP), evaluates
check items, applies groups and encodes reply items.

## Example

```java
public final class DirectoryStore implements IdentityStore {
    private final MyDirectory directory;

    DirectoryStore(MyDirectory directory) {
        this.directory = directory;
    }

    @Override
    public Optional<UserRecord> lookup(String userName) throws StoreUnavailableException {
        return directory.find(userName).map(u -> new UserRecord(
                userName,
                List.of(new AttributeItem("Cleartext-Password", ":=", u.password())),
                List.of(new AttributeItem("Class", ":=", u.plan())),
                List.of()));
    }

    @Override
    public void close() {}
}

public final class DirectoryStoreProvider implements IdentityStoreProvider {   // META-INF/services/io.radiusward.auth.IdentityStoreProvider
    @Override
    public String type() {
        return "directory";                                               // auth.store.<name>.type = directory
    }

    @Override
    public IdentityStore create(StoreContext context) {
        return new DirectoryStore(new MyDirectory(context.settings().get("url")));
    }
}
```

In a cluster, the jar goes on the class path or into `auth.plugins.dir`, and `auth.stores` lists the store's name.
In a test, `EmbeddedRadiusward.builder().identityStore(new DirectoryStore(...))` uses the same class without the
service file.

## Requirements

Java 25. Depends only on `radiusward-units`.

## Learn more

- [ADR 0021: identity stores](../docs/adr/0021-identity-stores.md), [ADR 0025: credential verifiers](../docs/adr/0025-credential-verifiers-and-ldap.md)
- [Configuration: identity stores](../docs/configuration.md#identity-stores)
- The built-in stores as examples: [file](../stores/file/README.md), [SQL](../stores/sql/README.md), [LDAP](../stores/ldap/README.md)

## License

Apache-2.0.
