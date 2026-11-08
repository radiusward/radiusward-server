# radclient

Command-line RADIUS accounting client for testing radiusward or any RADIUS server.

```bash
./mvnw -pl tools/radclient -am package -DskipTests
java -jar tools/radclient/target/radclient.jar --help
```

```bash
# build and send an Accounting-Request, wait for and verify the response
radclient acct --server 127.0.0.1:1813 --secret testing123 \
               --status start|interim|stop|on|off --session-id abc123 \
               [--vendor cisco|juniper|juniper-erx|mikrotik|huawei|meraki|ruckus] [--user alice] [--nas-ip 192.0.2.1] \
               [--attr Name=Value]... [--message-authenticator] [--id N] [--retries 3] [--timeout 3s]

# re-sign and send a recorded packet (fixture or hex file)
radclient replay radius-codec/src/test/resources/fixtures/huawei/interim.fixture --server 127.0.0.1:1813 --secret s

# pretty-print a packet
radclient decode 0401001a00000000000000000000000000000000280600000002
```

- `--attr` takes dictionary names, including vendor paths (`Cisco.AVPair=...`); integers accept `VALUE`
  names (`NAS-Port-Type=Virtual`), any type accepts `0x` hex.
- Retransmissions resend the identical datagram, like a NAS, which is what radiusward's deduplication
  has to handle.
- `--dictionary-dir` adds operator dictionaries.
- Exit codes: `0` verified Accounting-Response, `1` no response, `2` invalid or unauthentic response,
  `64` usage error.

The optional interop test (`./mvnw -Pinterop verify`) replays every vendor fixture against a local
FreeRADIUS (`brew install freeradius-server`); it is skipped when `radiusd` is not installed.
