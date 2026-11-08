# gateway

The RADIUS UDP front end ([ADR 0006](../docs/adr/0006-nio-udp-transport.md), [ADR 0011](../docs/adr/0011-gateway-pipeline.md)).

```bash
java -jar distribution/target/radiusward.jar gateway --config config/local/gateway-a.properties --config config/local/nas-clients.properties
```

| Class | Role |
|---|---|
| `UdpAgent` | owns the NIO socket: validate, NAS lookup, authenticators, response cache, extract, event keys, submit; builds and sends the response after commit |
| `ClusterClientAgent` | owns the Aeron Cluster client: `tryClaim` into the cluster, polls egress while back-pressured, reconnects |
| `NasRegistry`, `NasClient` | configured NAS by source address (IPv4 exact, allocation-free; CIDR), secret, Message-Authenticator policy |
| `EventKeys`, `Murmur3` | session key and exact key (pinned layout) |
| `ResponseCache` | RFC 5080 duplicate detection, state only (PENDING with correlation id / COMMITTED) |
| `PendingTable` | preallocated in-flight requests |
| `Gateway`, `GatewayConfig`, `GatewayMain` | wiring, embedded media driver, threading, management |

Never blocks and never allocates per packet (`GatewayAllocationIT`, 100k packets). A retransmit of a request
pending for over 1 s is resubmitted, so commands lost with a failed leader are recovered.
