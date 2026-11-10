# ADR 0046: NAS entries from a database

Status: Accepted (2026-11-10). Phase 5, work package 5.22 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
NAS entries are configured (`nas.<name>.*`). Large fleets, such as access points added daily, managed CPE, or
customer routers, keep their NAS in a database instead, and other servers read them on demand from a `nas` table
(`nasname`, `shortname`, `secret`, `type`). Reloading the configuration for every new device does not scale.

## Decision
- **`nas.dynamic.*`**: a packet from an address that no configured entry covers, inside `nas.dynamic.networks`
  (CIDR, prefix 8 to 32), makes the gateway look the address up.
  - The source is SQL over JDBC: `nas.dynamic.sql.url`, `.user`, `.password`. The query (`nas.dynamic.sql.query`,
    default `SELECT nasname, shortname, secret, type FROM nas WHERE nasname = ?`) gets the address as text.
  - The driver comes from the class path, as for the `sql` identity store; the distribution ships PostgreSQL's.
- **Never on the packet path**:
  - the packet that caused the lookup is dropped, and the NAS sends it again;
  - one background thread does the lookups from a bounded queue, one at a time per address;
  - found entries go into a copy-on-write table (Agrona `Int2ObjectHashMap`, replaced on change) that the packet
    path reads without locks or allocation, after the configured exact and range entries, so configured entries
    always win.
- **Lifetime**:
  - an entry is used for `nas.dynamic.lifetime` (1 h), then looked up again on the next packet, so a changed secret
    or a removed NAS takes effect within that time;
  - an address the source does not know (or with an empty secret) is not asked for again before
    `nas.dynamic.negative.ttl` (1 min);
  - a failing source is logged and asked again with the next packet;
  - at most `nas.dynamic.max` (10,000) entries are held.
- **The entry**:
  - name `dynamic:<shortname>`;
  - id the FNV-1a hash of `dynamic:<address>`, the same on every gateway, so its events deduplicate across
    gateways;
  - the row's secret; vendor from `type`, lower-cased;
  - Message-Authenticator optional on accounting and required on Access-Requests, as for configured entries;
  - no device identity, no RadSec, DTLS or TCP, CoA to its address.
- **No configured entry is needed** when `nas.dynamic.enabled`.
- **Metrics**: `radiusward_gateway_nas_dynamic_total{result}` (lookups, found, not_found, failed, queue_full,
  expired) and `radiusward_gateway_nas_dynamic_entries`.

## Tests
- `DynamicClientsTest`, with a fake source:
  - one lookup, then served from the table; the entry's name, secret, vendor and stable id;
  - addresses outside the networks never looked up;
  - the negative TTL; expiry after the lifetime;
  - a failing source retried;
  - the bound;
  - configuration and a registry without configured entries.
- `DynamicClientsIT`: through a gateway with no configured NAS and PostgreSQL holding a `nas` table, the first
  Access-Request is dropped and the retransmission answered, signed with the table's secret.
