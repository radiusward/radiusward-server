# radiusward-sink-radius

A built-in sink that forwards the committed accounting of proxied realms to their home servers, over UDP or RadSec.
The cluster has already committed and answered every event; this sink sends it on as an Accounting-Request (its
original attributes, Acct-Delay-Time raised, a new Message-Authenticator for the home server's secret) and counts a
batch written only when every request in it is acknowledged. `radiusward-sink-radius` is enabled with
`sink.<name>.type = radius`; operators set it up in a cluster's settings, no code needed.

**Stability:** Internal: published as a dependency of the cluster node (`radiusward-cluster-node`) and through it `radiusward-embedded`; it may change in any release.

## Use it

You normally do not depend on it directly: every cluster member (`radiusward.jar cluster-node`, the image) has it,
and it comes with [`radiusward-embedded`](../../embedded/README.md), where `setting(...)` enables it with the keys
below. In the embedded server keep its own sink first, `setting("export.sinks", "embedded, partner")`: the setting replaces the whole list, and `embedded` is the sink behind `accounting()` and `awaitAccounting(...)`. To write a sink of your own, use [`radiusward-export-api`](../../export-api/README.md).

## What's inside

| Type | Role |
|---|---|
| `RadiusSinkProvider` | the `SinkProvider` for `type = radius`, registered in `META-INF/services` |
| `RadiusSink` | sends the events of forwarded realms to the first home server that acknowledges them all, trying the servers in order; `CheckpointStyle.IDEMPOTENT_REPLAY` |
| `ForwardedRequest` | picks the events whose User-Name has a forwarded realm (`user@realm` or `REALM\user`) and builds the request's attributes: the originals, Acct-Delay-Time raised by the time since the commit, the realm stripped if configured |

A home server that is down makes the exporter keep the batch and try again: nothing is lost, and the NAS was never
kept waiting. One exporter at a time forwards (the sink's lease); after a failover the last batch may reach the home
server again, as RADIUS accounting allows.

## Configuration

```properties
export.sinks = partner
sink.partner.type    = radius
sink.partner.mode    = sessions+events
sink.partner.realms  = partner.example          # or * for every realm
sink.partner.servers = 192.0.2.10:1813, 192.0.2.11:1813
sink.partner.secret  = ${env:PARTNER_ACCT_SECRET}
# sink.partner.transport = tls                  # RadSec: tls.certificate, tls.key, tls.ca, tls.name; port 2083
# sink.partner.timeout = 3s, retries = 2, strip = false
```

| Key | Default | Meaning |
|---|---|---|
| `sink.<name>.mode` | — | must be `sessions+events` (the sink forwards events) |
| `sink.<name>.realms` | — (required) | realms to forward, comma-separated, case-insensitive; `*` for every realm |
| `sink.<name>.servers` | — (required) | home servers, `host[:port]`, tried in order; port `1813`, or `2083` with `tls` |
| `sink.<name>.secret` | — (`radsec` with `tls`) | the home servers' shared secret; required over UDP |
| `sink.<name>.transport` | `udp` | `udp` or `tls` (RadSec) |
| `sink.<name>.tls.certificate` / `.tls.key` | — | client certificate and key (PEM) for RadSec |
| `sink.<name>.tls.ca` | — (required with `tls`) | CAs (PEM) the home server's certificate must chain to |
| `sink.<name>.tls.name` | the server's host | the name checked in the home server's certificate |
| `sink.<name>.timeout` | `3s` | wait for an Accounting-Response; a bare number is seconds |
| `sink.<name>.retries` | `2` | resends to one home server before the next is tried; when none acknowledges, the batch is tried again later |
| `sink.<name>.strip` | `false` | send the User-Name without the realm |

The general sink keys (`required`, `max.lag`, `on.max.lag`, `batch.rows`, …) are in
[configuration.md](../../docs/configuration.md#export).

## Requirements

Java 25. Depends on `radiusward-export-api` and `radiusward-codec` (Agrona, Apache-2.0); TLS from the JDK.

## Learn more

- [ADR 0037: proxying](../../docs/adr/0037-proxying.md), [ADR 0034: RadSec](../../docs/adr/0034-radsec.md)
- [Export](../../docs/operations/export.md), [proxying settings of the RADIUS server](../../docs/configuration.md#proxying-server)
- [Writing a sink](../../docs/sinks/writing-a-sink.md)
- [`radiusward-export-api`](../../export-api/README.md), [`radiusward-server`](../../server/README.md)

## License

Apache-2.0.
