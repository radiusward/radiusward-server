# ADR 0051: A small rule layer

Status: Accepted (2026-11-10). Phase 5, work package 5.27 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Reply items come from users and groups. Deployments also need decisions that depend on the request: other attributes
for Wi-Fi than for VPN, a VLAN per access point, rejecting test accounts on production NAS, a message naming the NAS.
Other servers have a policy language for this; it is large, and much of it (modules, loops, database calls) is what
radiusward does in Java or through the stores.

## Decision
- **`auth.rules`**: a file of rules, run in order on every Access-Accept after the credentials, `Simultaneous-Use`,
  login times, counters and pools ([ADR 0049](0049-time-and-usage-limits.md), [ADR 0050](0050-ip-pools.md)):

  ```
  # comment
  if NAS-Port-Type == Wireless-802.11 && Group == guests {
      reply Session-Timeout := 3600
      reply Filter-Id = "guest-%{Called-Station-Id}"
      remove Framed-IP-Address
      stop
  }
  if User-Name =~ "^test-" && NAS-Identifier absent {
      reject
  }
  ```

- **Conditions**, all of which must hold: a standard request attribute compared like check items
  (`== != =~ !~ < > <= >=`), `present` / `absent`, or `Group == name` / `Group != name` (a group of the user whose
  check items hold). No `||` and no nesting: one rule per alternative.
- **Actions**: `reply <attribute> = value` (only if the reply lacks it), `:=` (replace), `+=` (add); `remove
  <attribute>`; `reject`; `stop` (no further rules). `%{Attribute}` in a value is the request's attribute.
- Attributes are checked against the dictionary and patterns compiled when the file is read; a file that does not
  parse stops the gateway at start, and a later broken edit keeps the previous rules (`auth.rules.reload.interval`).
- Rules run on the worker threads with the reply items, before encoding; the packet path is untouched.

## Consequences
- Rules see the outer request; inside EAP tunnels that is the outer identity, not the inner one.
- Vendor-specific attributes can be set and removed, not compared.
- Anything beyond this (external calls, loops, variables) stays in stores, verifiers and plug-ins.
