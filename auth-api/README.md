# auth-api

The identity store plug-in API ([ADR 0021](../docs/adr/0021-identity-stores.md)). A store implements
`IdentityStoreProvider` (its `type()` is what `auth.store.<name>.type` names) and registers it in
`META-INF/services/io.radiusward.auth.IdentityStoreProvider`; jars go on the class path or in `auth.plugins.dir`.

| Type | Role |
|---|---|
| `IdentityStoreProvider` | `type()` and `create(StoreContext)`; settings errors as `IllegalArgumentException` |
| `StoreContext` | store name, its `auth.store.<name>.*` settings, the number of worker threads (size pools to it) |
| `IdentityStore` | `lookup(userName)`: the user, empty if unknown, `StoreUnavailableException` if it cannot tell; called from several worker threads at once; must return within its own timeout |
| `UserRecord`, `AttributeItem` | check items, reply items and groups as attribute name, operator and text value |

Stores contain no RADIUS logic: the gateway verifies passwords, evaluates check items and encodes reply items.
