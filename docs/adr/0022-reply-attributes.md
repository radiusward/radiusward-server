# ADR 0022: Reply attributes and NAS vendors

Status: Accepted (2026-11-09). Phase 5, work package 5.4 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
An Access-Accept tells the NAS what the user gets: session and idle timeouts, filters, VLANs, bandwidth. Much of it
is vendor-specific (`Mikrotik-Rate-Limit`, `Cisco-AVPair`, `Huawei-Input-Peak-Rate`), and one site often runs
several vendors for the same users. Operators already keep these attributes per user and per group (ADR 0021). The
question is how one user or group can serve NAS devices of different vendors without a policy language.

## Decision
- **Reply attributes are data**: the user's reply items plus those of the groups that apply (`+=` always, `=`/`:=`
  only if the user did not set the attribute). No scripting, no vendor-neutral templates, no further policy rules
  beyond the check items of ADR 0021.
- **Vendor filter per NAS entry**: an Accept carries standard attributes always and vendor attributes only of the
  NAS entry's vendors. `nas.<name>.reply.vendors` lists them (dictionary vendor names, `all`, or `none`); by default
  they come from `nas.<name>.vendor` when it names a dictionary vendor (Juniper also gets the E-series vendor 4874),
  and an entry whose vendor is `default` or unknown gets every item. So one group can hold every vendor's
  attributes, and each NAS receives the ones it understands, in a smaller packet. Left-out attributes are counted
  per NAS entry (`radiusward_gateway_access_reply_items_filtered_total`).
- **Reply items are checked where possible**: a store that reads all users up front (the users file) checks every
  reply item against the dictionary at load and on reload and reports the line; others (SQL) are checked when first
  used, logged once and left out.
- **Encoded once**: each distinct reply item is encoded once per worker and kept; the per-worker caches are Agrona
  maps owned by the worker (single writer, no locks), like the agents' own tables.
- **Large replies** up to the RADIUS maximum (4096 bytes) are kept in the reply cache in a second, smaller ring, so a
  retransmission of a reply with many attributes is answered from the cache, not decided again.

## Consequences
- Mixed-vendor sites need no conditions: one group with every vendor's attributes is enough.
- A NAS entry covering devices of several vendors must list them in `nas.<name>.reply.vendors` (or use `all`).
- The vendor-neutral templates, login hours, the signed Class token and reject reasons in metrics were considered
  for 5.4 and deferred until operators ask for them.
