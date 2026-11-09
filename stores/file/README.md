# store-file

`auth.store.<name>.type=file`: users from a text file, for tests and small sites
([ADR 0021](../../docs/adr/0021-identity-stores.md)).

```text
# user name and check items on one line, reply items indented below, separated by commas
alice   Crypt-Password := "$6$rounds=5000$Xq3p$...", NAS-Port-Type == Wireless-802.11
        Session-Timeout = 3600,
        Reply-Message = "Welcome",
        Cisco-AVPair += "ip:inacl#1=permit ip any any"

guest   Cleartext-Password := "guest", Expiration := "Dec 31 2026"
```

- Operators: `:=`, `=`, `+=`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `=~`, `!~`, `=*`, `!*`. Values may be quoted
  (`\"`, `\\`, `\n`, `\t`).
- `DEFAULT` entries, `Fall-Through` and groups are not supported; a user name may appear once.
- Settings: `path` (required), `reload.interval` (default `5s`). The file is re-read when its modification time
  changes; a file with errors is logged with its line number and the previous users stay in use.
