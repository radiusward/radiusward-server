# ADR 0021: Identity stores

Status: Accepted (2026-11-09). Phase 5, work package 5.3 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
The Access-Request workers (ADR 0020) need users: their credentials, conditions and reply attributes. Sites keep
them in very different places — a database shared with a portal, a flat file, later LDAP or a REST service — and
many already have a `radcheck`/`radreply` schema. Looking a user up is I/O that can be slow or fail; the answer to
the NAS must never become Accept because of it.

## Decision
- **Plug-in SPI** (`auth-api`): `IdentityStoreProvider` (a `type` and a factory) creates an `IdentityStore` whose
  only operation is `lookup(userName)` → a `UserRecord` (check items, reply items, groups with their own check and
  reply items) or empty; `StoreUnavailableException` when it cannot tell. Providers come from the class path and
  from jars in `auth.plugins.dir`, through `ServiceLoader` — the same model as sinks (ADR 0007).
- **Stores run in the gateway**, on the `gateway.auth.workers` threads; the cluster is not involved. A store may
  block a worker up to its own timeout; the socket thread never waits.
- **Configuration**: `auth.stores` is the ordered list of store names, `auth.store.<name>.*` their settings
  (`type` picks the provider; the rest goes to it), `nas.<name>.auth.stores` an optional list per NAS entry.
- **Order and outages**: stores are asked in order and the first one that knows the user decides. If a store is
  unavailable and no later store knows the user, the request is not answered (the NAS retries or fails over) —
  an outage never turns into Accept, and never into Reject of a user the missing store might know.
- **Built-in stores**: `file` (a users file in the familiar `user check-items` / indented `reply-items` syntax,
  reloaded when it changes; a broken file keeps the previous users) and `sql` (JDBC with the `radcheck`,
  `radreply`, `radusergroup`, `radgroupcheck`, `radgroupreply` tables, table names configurable, our own small
  bounded connection pool — no pool library, no ORM).
- **Credentials**: `Cleartext-Password`, `Crypt-Password` (`$5$`/`$6$` SHA-crypt, `$2a$`/`$2b$`/`$2y$` bcrypt),
  `SSHA-Password`, `SSHA2-224/256/384/512-Password`, `PBKDF2-Password`. All are verified by our own code on JDK
  primitives — no runtime dependency; radiusward only verifies, never creates hashes. bcrypt is checked against
  the published vectors and, in tests only, against Bouncy Castle over random passwords and salts. A bcrypt cost
  above `auth.bcrypt.max.cost` (14) is rejected without hashing, so one bad row cannot occupy a worker for minutes.
  argon2 and yescrypt are not supported until there is demand; a user with only such a hash is rejected. CHAP uses `Cleartext-Password` and only for stores with
  `auth.store.<name>.chap = true`.
- **Check items** are conditions: `Auth-Type := Reject/Accept`, `Expiration` (an unparseable date fails closed),
  comparisons (`==`, `!=`, `<`, `>`, `<=`, `>=`, `=~`, `!~`) against request attributes. A group applies when its
  check items match; its reply items add to the user's (`+=` always, `=`/`:=` only if the user did not set the
  attribute). `Simultaneous-Use` is ignored until work package 5.5 and logged once.
- **Caching**: look-ups (including "unknown user") are cached per worker for `auth.cache.ttl` (5 s), so a
  reconnect storm costs at most one look-up per user and worker (ADR 0022: per-worker Agrona maps); successful slow-hash verifications (PBKDF2, SHA-crypt) are cached
  under the user plus a salted digest of the presented password, never the password itself.

## Consequences
- A database or file outage is visible to the NAS as silence; the gateway logs it once per cause.
- Changing a user takes effect within `auth.cache.ttl` (and `reload.interval` for the file store).
- Reply items are encoded through the dictionary; v3-style vendor names (`Cisco-AVPair`) and v4 paths
  (`Cisco.AVPair`) both work. Items the dictionary does not know are left out with a warning.
- New stores (`rest`, `ldap`) are plug-ins against the same SPI.
