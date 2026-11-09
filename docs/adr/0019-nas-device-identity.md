# ADR 0019: Devices behind one NAS entry (NAT)

Status: Accepted (2026-11-09). Plan and work items: [plans/nas-identity.md](../plans/nas-identity.md).

## Context
A NAS entry is found by the packet's source address; its id was part of the session key and scoped
Accounting-On/Off. Cloud-managed Wi-Fi (Meraki, Aruba Instant, Ruckus, UniFi, Cambium, Aerohive, Open-Mesh) sends
accounting from every access point, often through one NAT address. One entry then covers many devices: an
Accounting-On from one AP stopped the sessions of all of them, and two APs numbering sessions alike (`00000001`
after boot; RFC 2866 asks for uniqueness per NAS only) shared one session. A production system we studied identifies
the hotspot from attributes for this reason.

## Decision
- `nas.<name>.identity` lists request attributes that tell the devices behind an entry apart: `nas-identifier`,
  `called-station-id` (its MAC, normalised to 12 lower-case hex digits, `:SSID` dropped), `nas-ip-address`; the first
  present and non-empty one wins. Default `source-ip`: no attribute, keys byte-identical to before. An entry for
  `0.0.0.0/0` must set it (configuration error otherwise).
- The gateway resolves the identity allocation-free (`DeviceIdentity`). Both 128-bit keys cover
  `nasId, length, identity` before the session id, so devices never share a session. The **device scope** — a 32-bit
  hash of entry id and identity — is sent as the command's `nasId`; the state machine, store and snapshots are
  unchanged and group sessions, and Accounting-On/Off, per device. A scope collision (≈1 % among 10,000 devices of
  one entry) only widens an Accounting-On/Off to the two devices; sessions never collide.
- Protocol v3 appends `nasClientId` (the entry), `identityFingerprint`, `nasDevice` (the normalised identity) and the
  flag `deviceUnknown`. Without the identity attribute, Start/Interim/Stop use the entry's own scope (as before) and
  an Accounting-On/Off is acknowledged but **stops nothing** (stopping the whole entry is the failure this fixes);
  gateway counter `identity_missing`.
- Export: `nas_id` is the entry, new `nas_device` (PostgreSQL migration V2, `radacct.nasidentifier`); a session's
  `nas_id` is no longer updated after its first write.
- The cluster counts commands of an entry whose identity setting differs from the first seen
  (`radiusward_nas_identity_mismatches_total`): every gateway must configure an entry alike.

## Consequences
- **Choose an attribute the devices send in every accounting packet.** RFC 2866 requires NAS-IP-Address *or*
  NAS-Identifier; vendors differ in which, and Called-Station-Id is often missing from Interim and Stop. A session
  whose packets resolve to different attributes splits (the fixtures show it: Huawei and Ruckus send NAS-Identifier
  only in the Start, Juniper NAS-IP-Address only in the Start). Hence one entry per device fleet, and the gateway
  counter `identity_fallback` for packets that needed a later attribute of the list.
- NAS-IP-Address behind NAT is a private address that may repeat across sites: give each site's public address its
  own entry, or use NAS-Identifier.
- All devices of an entry share its secret, so one can claim another's identity (send its accounting or an
  Accounting-On). That is the trust domain the entry always had; the identity partitions sessions, it does not
  authenticate. Narrow address ranges and `message-authenticator=required` are recommended.
- Changing `identity` changes session keys: active sessions continue as new ones and the old ones end by the idle
  timeout — a maintenance-window change.
- A closure without an event of its own (NAS restart, idle timeout) of a device behind NAT exports the device scope
  as `nas_id`, since the replicated state keeps only that; sinks keep the session's first `nas_id`.
- Deferred until captures exist: mapping a Meraki AP's several BSSIDs to one AP, per-vendor default identities.
