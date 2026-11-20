# radiusward-store-sql

A built-in identity store that reads users from a database over plain JDBC, in the radcheck/radreply schema: per-user
check and reply items, group membership, per-group check and reply items. It lets radiusward take over existing user
tables without changing them. `radiusward-store-sql` is enabled with `auth.store.<name>.type = sql`; operators set it
up in a RADIUS server's settings, no code needed.

**Stability:** Internal: published as a dependency of the distribution (`radiusward.jar`); it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward.jar server` and the image have it. With
[`radiusward-embedded`](../../embedded/README.md), add it as a test dependency and enable it through `setting(...)`
with the keys below. To write an identity store of your own, use [`radiusward-auth-api`](../../auth-api/README.md).

## What's inside

| Type | Role |
|---|---|
| `SqlStoreProvider` | the `IdentityStoreProvider` for `type = sql`, registered in `META-INF/services` |
| `SqlStore` | four parameterised queries per look-up on one pooled connection: the user's check and reply items, and the check and reply items of their groups (joined through `radusergroup`) |
| `ConnectionPool` | a small bounded JDBC pool without dependencies: opened on demand, idle connections validated before use, failed ones closed |

Tables (column names fixed, table names configurable with `table.<table>`):

```sql
-- per-user conditions and credentials, per-user reply attributes
CREATE TABLE radcheck  (id serial PRIMARY KEY, username text NOT NULL, attribute text NOT NULL,
                        op varchar(2) NOT NULL DEFAULT '==', value text NOT NULL);
CREATE TABLE radreply  (LIKE radcheck INCLUDING ALL);
-- group membership, lower priority first
CREATE TABLE radusergroup (id serial PRIMARY KEY, username text NOT NULL, groupname text NOT NULL,
                           priority integer NOT NULL DEFAULT 1);
-- per-group conditions and reply attributes
CREATE TABLE radgroupcheck (id serial PRIMARY KEY, groupname text NOT NULL, attribute text NOT NULL,
                            op varchar(2) NOT NULL DEFAULT '==', value text NOT NULL);
CREATE TABLE radgroupreply (LIKE radgroupcheck INCLUDING ALL);
CREATE INDEX ON radcheck (username);
CREATE INDEX ON radreply (username);
CREATE INDEX ON radusergroup (username);
```

- Four queries per look-up (items ordered by `id`, groups by `priority`), all parameterised; table names start with a letter or `_` and
  contain only letters, digits, `_` and `.` (`schema.table`).
- Connections: a bounded pool of up to `pool` connections, opened on demand, validated after 30 s idle. Waiting
  longer than `timeout` for a connection or a query, or any SQL error, makes the store unavailable for that
  request: the request is not answered, and the NAS retries.
- radiusward only reads these tables; it never creates or changes them.

## Configuration

```properties
server.auth.enabled=true
auth.stores=db
auth.store.db.type=sql
auth.store.db.url=jdbc:postgresql://db:5432/radius
auth.store.db.user=radiusward
auth.store.db.password=${env:DB_PASSWORD}
auth.store.db.timeout=1500ms
```

| Key | Default | Meaning |
|---|---|---|
| `auth.store.<name>.url` / `.user` / `.password` | — / empty / empty | JDBC URL and credentials |
| `auth.store.<name>.pool` | `server.auth.workers` | maximum connections |
| `auth.store.<name>.timeout` | `1500ms` | wait for a connection, and query timeout; beyond it the store counts as unavailable |
| `auth.store.<name>.schema` | `radcheck` | table layout (only `radcheck` so far) |
| `auth.store.<name>.table.<table>` | the table's name | other names for `radcheck`, `radreply`, `radusergroup`, `radgroupcheck`, `radgroupreply` (`[schema.]name`) |
| `auth.store.<name>.chap` / `.mschap` | `false` | allow CHAP and EAP-MD5, or MS-CHAP, with `Cleartext-Password` |

All store keys are in [configuration.md](../../docs/configuration.md#identity-stores).

## Requirements

- Java 25.
- A JDBC driver on the class path or in `auth.plugins.dir`; the PostgreSQL JDBC driver (pgjdbc, BSD-2-Clause) is
  included.
- `radiusward-auth-api` and the Log4j 2 API (Apache-2.0).

## Learn more

- [ADR 0021: identity stores](../../docs/adr/0021-identity-stores.md), [ADR 0022: reply attributes](../../docs/adr/0022-reply-attributes.md)
- [Configuration: identity stores](../../docs/configuration.md#identity-stores)
- [`radiusward-auth-api`](../../auth-api/README.md), [`radiusward-store-file`](../file/README.md),
  [`radiusward-store-ldap`](../ldap/README.md), [`radiusward-server`](../../server/README.md)

## License

Apache-2.0.
