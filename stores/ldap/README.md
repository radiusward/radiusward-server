# store-ldap

Users from an LDAP directory (Active Directory in particular) and a password verifier that binds as the user
([ADR 0025](../../docs/adr/0025-credential-verifiers-and-ldap.md)). JDK LDAP client, no extra dependency.

```properties
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

| Setting | Default | Meaning |
|---|---|---|
| `url` | — | `ldap://` or `ldaps://` URLs, tried in order |
| `tls.ca` | the JDK's CAs | PEM file with the CA(s) of the directory's certificate (`ldaps://` only) |
| `bind.dn` / `bind.password` | anonymous | service account for searches |
| `base.dn` | — | where users and groups are searched |
| `user.filter` | `(&(objectClass=user)(sAMAccountName={0}))` | `{0}` is the escaped user name |
| `group.attribute` | `memberOf` | attribute with the user's group DNs |
| `group.nested` | `false` | groups of groups too (Active Directory's in-chain rule) |
| `require.groups` | none | comma-separated; outside all of them the user is rejected |
| `policy.<id>.group` / `.check` / `.reply` | — | items for members of a group, in id order |
| `check.<attribute>` / `reply.<attribute>` | — | RADIUS item from an LDAP attribute (several values: `+=`) |
| `timeout` | `1500ms` | connect, read and search time limit; beyond it the store is unavailable |
| `pool` | `gateway.auth.workers` | service-account connections |

Domain controllers refuse simple binds without TLS: use `ldaps://`. Disabled and expired Active Directory accounts
(`userAccountControl`, `accountExpires`) get `Auth-Type := Reject`. The verifier checks PAP only; MS-CHAP needs the
Netlogon verifier.
