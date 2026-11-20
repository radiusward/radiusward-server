# radiusward-store-file

A built-in identity store that reads users from a text file in the users file format: a user name with check items on
one line, reply items indented below. It suits tests, labs and small sites, and it is re-read when the file changes.
`radiusward-store-file` is enabled with `auth.store.<name>.type = file`; operators set it up in a RADIUS server's
settings, no code needed.

**Stability:** Internal: published as a dependency of the distribution (`radiusward.jar`); it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward.jar server` and the image have it. With
[`radiusward-embedded`](../../embedded/README.md), add it as a test dependency and enable it through `setting(...)`
with the keys below (the builder's `user(...)` covers the simple cases without a file). To write an identity store of
your own, use [`radiusward-auth-api`](../../auth-api/README.md).

## What's inside

| Type | Role |
|---|---|
| `FileStoreProvider` | the `IdentityStoreProvider` for `type = file`, registered in `META-INF/services` |
| `FileStore` | the users from `path`, read at start (an error stops the RADIUS server) and re-read when the file's modification time changes |
| `UsersFile` | the parser: entries, check and reply items, errors with their line number |

```text
# user name and check items on one line, reply items indented below, separated by commas
alice   Crypt-Password := "$6$rounds=5000$Xq3p$...", NAS-Port-Type == Wireless-802.11
        Session-Timeout = 3600,
        Reply-Message = "Welcome",
        Cisco-AVPair += "ip:inacl#1=permit ip any any"

guest   Cleartext-Password := "guest", Expiration := "Dec 31 2026"
"user with spaces"  Cleartext-Password := "secret"
```

- Operators: `:=`, `=`, `+=`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `=~`, `!~`, `=*`, `!*`. Values are bare words or
  double-quoted strings; inside quotes a backslash takes the next character as it is (`\"`, `\\`); no expansions.
- `DEFAULT` entries and `Fall-Through` are not supported and are rejected with the line number, so a file never
  means something other than it seems; groups are not supported either. A user name may appear once.
- Reply items are checked against the dictionary when the file is loaded: an unknown attribute or a value that
  cannot be encoded is an error with its line number.
- A changed file with errors is logged with its line number and the previous users stay in use.
- Stored password formats (cleartext, SHA-crypt, bcrypt, yescrypt, …) are checked by the RADIUS server
  ([ADR 0048](../../docs/adr/0048-password-formats.md)).

## Configuration

```properties
server.auth.enabled = true
auth.stores = local
auth.store.local.type = file
auth.store.local.path = /etc/radiusward/users
auth.store.local.reload.interval = 5s
```

| Key | Default | Meaning |
|---|---|---|
| `auth.store.<name>.path` | — (required) | the users file |
| `auth.store.<name>.reload.interval` | `5s` | how often the file's modification time is checked |
| `auth.store.<name>.chap` / `.mschap` | `false` | allow CHAP and EAP-MD5, or MS-CHAP, with `Cleartext-Password` |

All store keys are in [configuration.md](../../docs/configuration.md#identity-stores).

## Requirements

Java 25. Depends on `radiusward-auth-api` and the Log4j 2 API (Apache-2.0).

## Learn more

- [ADR 0021: identity stores](../../docs/adr/0021-identity-stores.md), [ADR 0022: reply attributes](../../docs/adr/0022-reply-attributes.md)
- [Configuration: identity stores](../../docs/configuration.md#identity-stores)
- [`radiusward-auth-api`](../../auth-api/README.md), [`radiusward-store-sql`](../sql/README.md),
  [`radiusward-store-ldap`](../ldap/README.md), [`radiusward-server`](../../server/README.md)

## License

Apache-2.0.
