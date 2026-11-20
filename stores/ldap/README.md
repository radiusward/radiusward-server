# radiusward-store-ldap

A built-in identity store that finds users, their groups and their RADIUS items in an LDAP directory, Active
Directory in particular, and a credential verifier that checks PAP passwords by binding as the user. Directories hold
no password radiusward can read, so the store and the verifier work as a pair. `radiusward-store-ldap` is enabled
with `auth.store.<name>.type = ldap` and `auth.verifier.<name>.type = ldap`; operators set it up in a RADIUS server's
settings, no code needed. It uses the JDK's LDAP client.

**Stability:** Internal: published as a dependency of the distribution (`radiusward.jar`); it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward.jar server` and the image have it. With
[`radiusward-embedded`](../../embedded/README.md), add it as a test dependency and enable it through `setting(...)`
with the keys below. To write an identity store or credential verifier of your own, use
[`radiusward-auth-api`](../../auth-api/README.md).

## What's inside

| Type | Role |
|---|---|
| `LdapStoreProvider`, `LdapStore` | the store (`type = ldap`): groups (`memberOf`, or nested), `require.groups`, policies per group, items mapped from directory attributes, Active Directory account state |
| `LdapVerifierProvider`, `LdapVerifier` | the verifier (`type = ldap`): the service account finds the user's DN with `user.filter`, then a bind with the password decides |
| `LdapSettings` | the settings both share (`auth.store.<name>.*` / `auth.verifier.<name>.*`) |
| `Directory` | a bounded pool of contexts bound as the service account for searches, and fresh binds as a user |
| `TlsSocketFactory` | trusts the CAs of `tls.ca` for `ldaps://` instead of the JDK's defaults; the host name is still checked |

- Disabled and expired Active Directory accounts (`userAccountControl`, `accountExpires`) get `Auth-Type := Reject`;
  so do users outside every group of `require.groups`.
- The directory applies its own rules to the bind (disabled, expired, locked accounts, password age).
- The verifier checks PAP only; MS-CHAP cannot be checked over LDAP and needs the
  [Netlogon verifier](../../verifiers/netlogon/README.md).
- Domain controllers refuse simple binds without TLS: use `ldaps://`.

## Configuration

```properties
server.auth.enabled = true
auth.stores = ad
auth.store.ad.type = ldap
auth.store.ad.url = ldaps://dc1.corp.example ldaps://dc2.corp.example
auth.store.ad.tls.ca = /etc/radiusward/corp-ca.pem
auth.store.ad.bind.dn = CN=svc-radius,OU=Service,DC=corp,DC=example
auth.store.ad.bind.password = ${env:LDAP_PASSWORD}
auth.store.ad.base.dn = DC=corp,DC=example
auth.store.ad.group.nested = true
auth.store.ad.require.groups = VPN Users
auth.store.ad.policy.10.group = Staff
auth.store.ad.policy.10.reply = Filter-Id = "staff", Session-Timeout = 28800
auth.store.ad.reply.Framed-IP-Address = radiusFramedIPAddress
auth.store.ad.verifier = ad-bind

auth.verifiers = ad-bind
auth.verifier.ad-bind.type = ldap
auth.verifier.ad-bind.url = ldaps://dc1.corp.example
auth.verifier.ad-bind.tls.ca = /etc/radiusward/corp-ca.pem
auth.verifier.ad-bind.bind.dn = CN=svc-radius,OU=Service,DC=corp,DC=example
auth.verifier.ad-bind.bind.password = ${env:LDAP_PASSWORD}
auth.verifier.ad-bind.base.dn = DC=corp,DC=example
```

Keys under `auth.store.<name>.` and `auth.verifier.<name>.`:

| Setting | Default | Meaning |
|---|---|---|
| `url` | — (required) | `ldap://` or `ldaps://` URLs, space- or comma-separated, tried in order |
| `tls.ca` | the JDK's CAs | PEM file with the CA(s) of the directory's certificate (`ldaps://` only) |
| `bind.dn` / `bind.password` | — (required) | service account for searches |
| `bind.anonymous` | `false` | `true`: search without `bind.dn`, for a directory that allows anonymous searches; users are still checked by binding as themselves, and an empty password is always refused |
| `base.dn` | — (required) | where users and groups are searched |
| `user.filter` | `(&(objectClass=user)(sAMAccountName={0}))` | `{0}` is the escaped user name |
| `strip.domain` | `true` | look `DOMAIN\user` and `user@realm` up as `user` (Windows clients send the former); `false` when `user.filter` matches the full `userPrincipalName` |
| `group.attribute` | `memberOf` | attribute with the user's group DNs |
| `group.nested` | `false` | groups of groups too (Active Directory's in-chain rule) |
| `require.groups` | none | comma-separated; outside all of them the user is rejected |
| `policy.<id>.group` / `.check` / `.reply` | — | items for members of a group, in id order, in the users file item syntax |
| `check.<attribute>` / `reply.<attribute>` | — | RADIUS item from an LDAP attribute (several values: `+=`) |
| `timeout` | `1500ms` | connect, read and search time limit; beyond it the store is unavailable |
| `pool` | `server.auth.workers` | service-account connections |

The store-only keys (`verifier`, `chap`, `mschap`) and the rest are in
[configuration.md](../../docs/configuration.md#identity-stores).

## Requirements

Java 25. The JDK's LDAP client (JNDI), no extra dependency beyond `radiusward-auth-api` and the Log4j 2 API
(Apache-2.0). Tests run against a Samba AD domain controller in a container ([`testing/samba-ad`](../../testing/samba-ad/README.md)).

## Learn more

- [ADR 0025: credential verifiers and LDAP](../../docs/adr/0025-credential-verifiers-and-ldap.md),
  [ADR 0021: identity stores](../../docs/adr/0021-identity-stores.md)
- [Configuration: identity stores](../../docs/configuration.md#identity-stores)
- [`radiusward-verifier-netlogon`](../../verifiers/netlogon/README.md), [`radiusward-auth-api`](../../auth-api/README.md),
  [`radiusward-store-sql`](../sql/README.md), [`radiusward-server`](../../server/README.md)

## License

Apache-2.0.
