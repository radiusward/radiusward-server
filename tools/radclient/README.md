# radclient

Command-line RADIUS client — accounting and authentication — for testing radiusward or any RADIUS server.

```bash
./mvnw -pl tools/radclient -am package -DskipTests
java -jar tools/radclient/target/radclient.jar --help
```

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
radclient decode <hex|file> --fixture [--anonymise] [--comment "Cisco ASR 1001-X, IOS-XE 17.9: interim"]

# load: sessions over simulated NAS, Start/Interim/Stop, paced, retransmitting, with an ack log
radclient load --server 127.0.0.1:1813,127.0.0.1:1814 --secret testing123 --nas 10 --sessions 1000 \
               --rate 1000 --duration 60s --interim 10s [--timeout 3s] [--retries 3] [--retry-other-server] \
               [--no-stop] [--ack-log acks.csv] [--first-session 0] [--shared-session-ids] \
               [--access-rate 100 [--auth-server 127.0.0.1:1812,...] [--auth-users alice,bob] [--auth-password p] \
                [--auth-methods pap,chap,mschapv2] [--reject-ratio 0.05]]
```

`auth` builds PAP (RFC 2865), CHAP (RFC 1994: CHAP-Challenge and CHAP-Password) or MS-CHAPv2 (RFC 2759:
MS-CHAP-Challenge and MS-CHAP2-Response) credentials; `--server` defaults to port 1812. It always sends
Message-Authenticator, which gateways require by default.

With `--access-rate`, `load` also sends that many Access-Requests per second for the same duration, round-robin over
`--auth-users` (default `load`), all with `--auth-password` (default `load`), and over `--auth-methods`; a
`--reject-ratio` share (default 5 %) carries a wrong password, so rejects appear too. They go to `--auth-server`, by
default the accounting servers' hosts on port 1812. `--sessions 0` sends Access-Requests only. The summary line
`access:` counts accepts, rejects, challenges, timeouts and unexpected answers (a wrong password accepted or a right
one rejected); either of the last two makes the exit code non-zero.

`load` prints sent/acked/failed/retransmissions and p50/p99/max latency; the ack log has one line per event
(`session_id,status,session_time,acked,attempts,latency_ms,nas_identifier`). Each simulated NAS sends its own
NAS-Identifier (`nas<n>`) from this one address, like access points behind NAT; `--shared-session-ids` makes them
reuse the same Acct-Session-Ids, which only a NAS entry with `identity = nas-identifier` keeps apart
([ADR 0019](../../docs/adr/0019-nas-device-identity.md)). It retransmits the identical datagram like a
NAS, so it exercises the gateways' response caches and the cluster's dedup. `radiusward admin verify-acks`
checks an ack log against the replicated state. `--sessions` is the total; the request rate is at most
sessions / interim. Several generators in parallel need distinct `--first-session` values.

- `--attr` takes dictionary names, including vendor paths (`Cisco.AVPair=...`); integers accept `VALUE`
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
- Retransmissions resend the identical datagram, like a NAS, which is what radiusward's deduplication
  has to handle.
- `--dictionary-dir` adds operator dictionaries.
- Exit codes: `0` verified Accounting-Response or Access-Accept, `1` no response, `2` invalid or unauthentic
  response, `3` Access-Reject or Access-Challenge, `64` usage error.

The optional interop test (`./mvnw -Pinterop verify`) replays every vendor fixture against a local
FreeRADIUS (`brew install freeradius-server`); it is skipped when `radiusd` is not installed.
