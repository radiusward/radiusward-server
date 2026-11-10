# ADR 0054: Reloading the gateway configuration

Status: Accepted (2026-11-10). Phase 5, work package 5.30 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Adding a NAS, changing a secret or pointing a store at another database meant restarting the gateway: EAP
conversations, TOTP challenges and reply caches were lost, and NAS retransmitted. Some files already reloaded
themselves (users files, certificates, CRLs, rules), the properties did not. Other servers reload on SIGHUP.

## Decision
- **Triggers**: SIGHUP (`systemctl reload`, `docker kill -s HUP`) and `POST /reload` on the management port with
  `Authorization: Bearer <reload.api.token>`. Both read the same `--config` files and environment again.
- **Validate first, then swap**: the new NAS table, identity stores, counters, pools, TOTP settings and rules file are
  all built before anything changes; a configuration that does not load is logged (and answered with 400) and the
  running one stays.
- **What changes**:
  - **NAS entries** (UDP: addresses, secrets, vendors, Message-Authenticator policy, ids): the registry swaps its table
    in one volatile write; a packet already received keeps the entry it came with; dynamic clients keep running.
  - **Identity stores**, their per-NAS lists, reply vendors and verifiers: new requests use the new ones; worker
    caches are dropped; the old stores are closed 30 s later so requests still using them finish.
  - Usage counters, IP pools, TOTP, CUI ([ADR 0056](0056-chargeable-user-identity.md)), the reject delay
    ([ADR 0057](0057-reject-delay.md)), the rules file and configured trace conditions; trace conditions from the API
    stay. The authentication log ([ADR 0058](0058-authentication-log.md)) is not reloaded.
- **What does not**: listening ports and addresses, workers, RadSec/DTLS/TCP clients, the cluster connection,
  proxying and home servers, CoA, EAP methods and their TLS settings (certificate files reload on their own). They
  need a restart; a reload leaves them as they are.
- EAP conversations and TOTP challenges in progress survive a reload: they live in the handler, which stays.

## Consequences
- Removing a NAS stops its requests at once; retransmissions of requests already in flight are still answered from
  the reply cache.
- A NAS whose `id` changes produces events with the new id from then on (as after a restart).
