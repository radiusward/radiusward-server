# store-sql

`auth.store.<name>.type=sql`: users from a database over plain JDBC, in the `radcheck` table layout
([ADR 0021](../../docs/adr/0021-identity-stores.md)). The JDBC driver goes on the class path or in
`auth.plugins.dir`; the PostgreSQL driver is included.

```properties
auth.stores=db
auth.store.db.type=sql
auth.store.db.url=jdbc:postgresql://db:5432/radius
auth.store.db.user=radiusward
auth.store.db.password=...
auth.store.db.timeout=1500ms
```

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

- Four queries per look-up (items ordered by `id`, groups by `priority`), all parameterised; table names may
  contain only letters, digits, `_` and `.` (`schema.table`).
- Connections: a bounded pool of up to `pool` connections (default `gateway.auth.workers`), opened on demand,
  validated after 30 s idle. Waiting longer than `timeout` for a connection or a query, or any SQL error, makes the
  store unavailable for that request — the request is not answered.
- radiusward only reads these tables.
