# radiusward-radclient

A command-line RADIUS client for testing radiusward or any RADIUS server: it sends accounting and Access-Requests and
verifies the answers, replays and decodes recorded packets, and generates load from many simulated NAS with an
acknowledgement log that `radiusward admin` checks against the cluster. `radiusward-radclient` is shipped in
`radiusward.jar` (the distribution) and the container image as `radclient`.

**Stability:** Internal: published as a dependency of the distribution (`radiusward.jar`); it may change in any release.

## Use it

You normally do not depend on it directly: run it from `radiusward.jar` or the image. To send RADIUS requests from
Java code or tests, use [`radiusward-client`](../../client/README.md) instead.

```bash
java -jar radiusward.jar radclient --help                         # the distribution
docker run --rm radiusward:dev radclient --help                    # the image
./mvnw -pl tools/radclient -am package -DskipTests                 # or a standalone jar from the sources
java -jar tools/radclient/target/radclient.jar --help
```

## What's inside

| Command | What it does |
|---|---|
| `acct` | builds and sends an Accounting-Request (Start, Interim, Stop, Accounting-On/Off), with vendor profiles, waits for and verifies the response |
| `auth` | sends an Access-Request with PAP, CHAP or MS-CHAPv2 and Message-Authenticator, verifies the Access-Accept or Access-Reject |
| `replay` | re-signs and sends a recorded packet (a fixture or a hex file) |
| `decode` | pretty-prints a packet with dictionary names, or turns a capture into a vendor fixture (`--fixture`) |
| `load` | sessions over simulated NAS, Start/Interim/Stop, paced, retransmitting, with an ack log; optionally Access-Requests beside them |

The classes behind them: `RadClient` (the command line), `PacketBuilder` and `PacketPrinter`, `UdpExchange`,
`LoadGenerator` and `AccessLoad` over `RequestPorts`, `FixtureWriter`.

## Example

```bash
# build and send an Accounting-Request, wait for and verify the response
radclient acct --server 127.0.0.1:1813 --secret testing123 \
               --status start|interim|stop|on|off --session-id abc123 \
               [--vendor aruba|cisco|huawei|juniper|juniper-erx|meraki|mikrotik|mikrotik-hotspot|open-mesh|ruckus|ubiquiti] [--user alice] [--nas-ip 192.0.2.1] \
               [--attr Name=Value]... [--message-authenticator] [--id N] [--retries 3] [--timeout 3s]

# send an Access-Request (with Message-Authenticator) and verify the Access-Accept or Access-Reject
radclient auth --server 127.0.0.1:1812 --secret testing123 --user alice --password secret \
               [--method pap|chap|mschapv2] [--nas-ip 192.0.2.1] [--calling-station-id 02-00-00-00-00-01] \
               [--attr Name=Value]... [--id N] [--retries 3] [--timeout 3s]

# re-sign and send a recorded packet (fixture or hex file)
radclient replay radius-codec/src/test/resources/fixtures/huawei/interim.fixture --server 127.0.0.1:1813 --secret s

# pretty-print a packet, or turn a capture into a vendor fixture (docs/testing/vendor-captures.md)
radclient decode 0401001a00000000000000000000000000000000280600000002
radclient decode <hex|file> --fixture [--anonymise] [--comment "device model, firmware: interim"]

# load: sessions over simulated NAS, Start/Interim/Stop, paced, retransmitting, with an ack log
radclient load --server 127.0.0.1:1813,127.0.0.1:1814 --secret testing123 --nas 10 --sessions 1000 \
               --rate 1000 --duration 60s --interim 10s [--timeout 3s] [--retries 3] [--retry-other-server] \
               [--no-stop] [--ack-log acks.csv] [--first-session 0] [--shared-session-ids] \
               [--access-rate 100 [--auth-server 127.0.0.1:1812,...] [--auth-users alice,bob] [--auth-password p] \
                [--auth-methods pap,chap,mschapv2] [--reject-ratio 0.05]]
```

Durations (`--timeout`, `--duration`, `--interim`) are written as in the settings: `250ms`, `3s`, `5m`, `1h`; a
number without a unit is seconds. Lists (`--server`, `--auth-users`, ...) are comma-separated.

**auth.** It builds PAP (RFC 2865), CHAP (RFC 1994: CHAP-Challenge and CHAP-Password) or MS-CHAPv2 (RFC 2759:
MS-CHAP-Challenge and MS-CHAP2-Response) credentials; `--server` defaults to port 1812. It always sends
Message-Authenticator, which RADIUS servers require by default.

**load.** It prints sent/acked/failed/retransmissions and p50/p99/max latency; the ack log has one line per event
(`session_id,status,session_time,acked,attempts,latency_ms,nas_identifier`). Each simulated NAS sends its own
NAS-Identifier (`nas<n>`) from this one address, like access points behind NAT; `--shared-session-ids` makes them
reuse the same Acct-Session-Ids, which only a NAS entry with `identity = nas-identifier` keeps apart
([ADR 0019](../../docs/adr/0019-nas-device-identity.md)). It retransmits the identical datagram like a NAS, so it
exercises the RADIUS servers' response caches and the cluster's dedup. `radiusward admin verify-acks` checks an ack
log against the replicated state. `--sessions` is the total; the request rate is at most sessions / interim. Several
generators in parallel need distinct `--first-session` values.

With `--access-rate`, `load` also sends that many Access-Requests per second for the same duration, round-robin over
`--auth-users` (default `load`), all with `--auth-password` (default `load`), and over `--auth-methods`; a
`--reject-ratio` share (default 5 %) carries a wrong password, so rejects appear too. They go to `--auth-server`, by
default the accounting servers' hosts on port 1812. `--sessions 0` sends Access-Requests only. The summary line
`access:` counts accepts, rejects, challenges, timeouts and unexpected answers (a wrong password accepted or a right
one rejected); either of the last two makes the exit code non-zero.

**Attributes and options.**

- `--attr` takes dictionary names, including vendor paths (`<Vendor>.<Attribute>=...`); integers accept `VALUE`
  names (`NAS-Port-Type=Virtual`), any type accepts `0x` hex.
- `Event-Timestamp` defaults to now; `--attr Event-Timestamp=<unix seconds>` replaces it, e.g. to send a delayed
  Start after its Interim:

  ```bash
  now=$(date +%s)
  radclient acct --server 127.0.0.1:1813 --secret testing123 --status interim --session-id s9 \
      --attr Acct-Session-Time=300 --attr Event-Timestamp=$now        # session created without a Start
  radclient acct --server 127.0.0.1:1813 --secret testing123 --status start --session-id s9 \
      --attr Event-Timestamp=$((now - 300))                         # late Start: acknowledged, merged
  ```
- Retransmissions resend the identical datagram, like a NAS, which is what radiusward's deduplication has to handle.
- `--dictionary-dir` adds operator dictionaries.
- Exit codes: `0` verified Accounting-Response or Access-Accept, `1` no response, `2` invalid or unauthentic
  response, `3` Access-Reject or Access-Challenge, `64` usage error.

The optional interop test (`./mvnw -Pinterop verify`) replays every vendor fixture against a locally installed
`radiusd`; it is skipped when `radiusd` is not installed.

## Requirements

- Java 25.
- `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` for Agrona; `radiusward.jar` and `radclient.jar` set it in
  their manifests.
- Depends on `radiusward-client`, `radiusward-codec` (Agrona, Apache-2.0), the bundled dictionaries,
  `radiusward-auth-api` and `radiusward-units`.

## Learn more

- [Testing strategy](../../docs/testing/strategy.md), [vendor captures](../../docs/testing/vendor-captures.md),
  [benchmarks](../../docs/testing/benchmarks.md)
- [Local cluster](../../docs/operations/local-cluster.md)
- [ADR 0019: NAS device identity](../../docs/adr/0019-nas-device-identity.md)
- [`radiusward-admin-cli`](../admin-cli/README.md), [`radiusward-client`](../../client/README.md),
  [`distribution`](../../distribution/README.md)

## License

Apache-2.0.
