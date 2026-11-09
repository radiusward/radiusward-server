# Plan: NAS devices behind NAT (device identity)

Status: implemented (2026-11-09) — [ADR 0019](../adr/0019-nas-device-identity.md). Decisions: `identity` explicit
(required for `0.0.0.0/0`), Accounting-On/Off without identity stops nothing, Meraki BSSID mapping deferred.
**Correction found by the vendor fixtures:** a fallback list is not a safe default — vendors send NAS-Identifier or
NAS-IP-Address in only some packets, and a session whose packets resolve to different attributes splits. One entry
per fleet with the attribute it sends in every packet; counter `identity_fallback`.

## Problem

A NAS is identified only by the packet's source address (`NasRegistry`, "never from attributes"). Its configured
id is part of the session key (`Murmur3-128(nasId, Acct-Session-Id)`) and scopes Accounting-On/Off (all active
sessions of that `nasId` stop).

Cloud-managed Wi-Fi (Meraki, Aruba Instant/Central, Ruckus Unleashed/Cloud, UniFi, Cambium, Aerohive, Open-Mesh)
sends accounting **from each access point**, and many APs reach us **through one NAT address** that may also change.
One `nas.<name>.address` (a CIDR range, or `0.0.0.0/0`) then covers hundreds of devices, and:

1. **Accounting-On/Off from one AP stops the sessions of every AP behind that address**: wrong closures, then
   "Interim after Stop" for the real sessions (stale) — wrong data for all of them.
2. **Two APs with the same Acct-Session-Id share one session.** Several devices number sessions per boot or from a
   counter (e.g. `00000001`); RFC 2866 asks for uniqueness only per NAS. Their events then fight over one session
   (stale, duplicate, wrong counters).
3. Exported rows cannot tell the APs apart (`nas_id` is the NAT entry).

Hotspot platforms commonly identify the access point from request attributes (NAS-Identifier, Called-Station-Id,
Aruba-Location-Id) for exactly this reason.

## Proposal

A NAS client entry gets an optional **device identity**: one or more request attributes that tell the devices behind
it apart. The gateway turns it into a **device scope**; everything that is "per NAS" today becomes per device.

```properties
nas.cloud.address  = 0.0.0.0/0                # or the NAT ranges
nas.cloud.secret   = ${env:CLOUD_SECRET}
nas.cloud.message-authenticator = required    # recommended for any-source entries
nas.cloud.identity = nas-identifier, called-station-id   # first present wins; default: source-ip
```

| `identity` value | Taken from | Normalised |
|---|---|---|
| `source-ip` (default) | nothing — today's behaviour, byte-identical keys | — |
| `nas-identifier` | NAS-Identifier (32) | as sent (bytes) |
| `called-station-id` | MAC part of Called-Station-Id (30) | 12 lower-case hex digits, `:SSID` suffix dropped; not a MAC → as sent |
| `nas-ip-address` | NAS-IP-Address (4) | 4 bytes (private addresses repeat across sites — documented) |

### Keys and scope

- **Session key** = Murmur3-128(nas id, identity bytes, Acct-Session-Id): full width, so devices never share a
  session. Exact key gets the same prefix. With `source-ip` the input is unchanged, so `EventKeysTest`'s vectors and
  all existing dedup state stay valid.
- **Device scope** (`int`) = nas id for `source-ip`, else a 32-bit hash of (nas id, identity bytes). It travels in
  the command's existing `nasId` field, so the state machine, `SessionStore`'s per-NAS list, snapshots and
  Accounting-On/Off need **no change**: an Accounting-On stops the sessions of its device only. A 32-bit collision
  (≈1 % at 10,000 devices of one entry) only widens an Accounting-On/Off to the two colliding devices; sessions never
  collide (128-bit). Documented.
- **Command** (protocol v3, appended): `nasClientId` (the configured id) and `nasDevice` (the normalised identity,
  ≤ 64 bytes), for export and operations.

### Missing identity attribute

| Packet | Behaviour | Why |
|---|---|---|
| Start / Interim / Stop | falls back to the entry's own scope (as today); counter `identity_missing` | an un-answered packet is retransmitted forever; one shared scope is today's behaviour |
| Accounting-On / Off | acknowledged, exact-key dedup only, **stops no session**; counter `nas_restart_without_identity` | stopping every device behind the NAT is the bug we are fixing; lost Stops are covered by the idle timeout |

### Export

`ExportEvent` / `SessionSnapshot` get `nasDevice`; PostgreSQL migration **V2**: `nas_device text` on
`accounting_session` and `accounting_event`, `nas_id` stays the configured entry, `radacct.nasidentifier` from
`nas_device` when present. File sink: one more field. `writing-a-sink.md` updated.

### Tooling

- `radclient load --devices N --nas-identifier-prefix ap-`: N simulated APs from one source address, reusing the
  same Acct-Session-Ids across devices (the collision case); ack log gets a `device` column.
- `admin verify-acks` / `verify-export`: compute keys with the device identity (shared `EventKeys`).

## Security

Within one entry all devices share the secret, so a device can claim another's identity — accounting for it, or an
Accounting-On that stops its sessions. That is the same trust domain as today (any holder of the secret can send any
Acct-Session-Id); the identity partitions sessions, it does not authenticate. Documented, with
`message-authenticator=required` and narrow address ranges recommended.

## Operations

- Every gateway must use the same `identity` for an entry (like `nas.<name>.id`). The command carries a fingerprint
  of the entry's identity config; the cluster counts and logs a mismatch between gateways (`identity_mismatch`).
- Changing `identity` on a running system changes session keys: active sessions continue as new sessions, the old
  ones end by the idle timeout. Do it in a maintenance window; documented in `configuration.md`.

## Work items

| # | Item | Size |
|---|---|---|
| 1 | Config + `NasClient` identity list, validation (`identity` values, Message-Authenticator advice for `/0`) | S |
| 2 | `EventKeys`: identity bytes in both keys, scope hash, MAC normaliser — zero allocation | M |
| 3 | `UdpAgent`: extraction (hot fields `nasIdentifier`, `calledStationId`, `nasIpAddress` exist), fallbacks, counters | S |
| 4 | Protocol v3 (`nasClientId`, `nasDevice`, identity fingerprint), round-trip test v2↔v3 | S |
| 5 | Cluster: Accounting-On/Off without identity stops nothing; mismatch counter | S |
| 6 | Exporter + export-api fields, PostgreSQL V2 migration, file sink, `radacct` view | M |
| 7 | radclient `load --devices`, admin verifiers | S |
| 8 | Docs: ADR 0019, configuration, accounting contract, architecture, writing-a-sink, monitoring | S |

## Tests

- **Unit:** `EventKeysTest` — `source-ip` vectors unchanged, new pinned vectors per identity; MAC normalisation
  (`AA-BB-CC-DD-EE-FF:Guest`, `aabb.ccdd.eeff`, `AABBCCDDEEFF`, not-a-MAC); scope hash. `NasRegistry` config
  validation. `UdpAgentTest`: two devices from one source address with the same Acct-Session-Id → two sessions;
  missing attribute → fallback + counter.
- **State machine:** Accounting-On of device A leaves device B's sessions active; On/Off without identity stops
  nothing.
- **Allocation:** `HotPathAllocationIT` / `GatewayAllocationIT` with `identity = nas-identifier, called-station-id`.
- **Cluster IT:** 3 members, 2 gateways, 50 simulated APs behind one address with colliding Acct-Session-Ids; one
  AP reboots (Accounting-On) — only its sessions stop; `verify-acks` clean.
- **Export:** `PostgresSinkTest` V2 migration from a V1 schema with data; `nas_device` filled; `PostgresExportIT`
  with devices.
- **e2e:** one process-based scenario: NAT entry, two devices, Accounting-On of one.
- **Fixtures:** Meraki (BSSID in Called-Station-Id), Aruba Instant (NAS-Identifier), Open-Mesh (empty
  NAS-Identifier → second identity attribute) — synthetic until captures exist.

## Open questions

1. Default list for a new any-source entry: `nas-identifier, called-station-id` (proposed) or explicit only?
2. Meraki: one AP has several BSSIDs (per SSID/radio); with `called-station-id` each BSSID is its own device. Fine
   for sessions; an AP-wide Accounting-On (if Meraki sends one) would need a per-vendor BSSID→AP mask. Defer until
   captures show it is needed.
3. IPv6 NAS addresses stay out of scope (registry is IPv4 today).
