# admin-cli

Queries the replicated state through the cluster log (`StateQuery`, `SessionQuery`), so every answer
includes everything committed before the query. Part of `radiusward.jar` as `radiusward admin`.

```bash
radiusward admin state       --members h0,h1,h2 [--base-port 9000] [--egress-host <own address>]
radiusward admin verify-acks --members h0,h1,h2 --ack-log acks.csv --nas-id 1001 [--egress-host ...]
```

- `state` prints applied/duplicates/stale/rejected counts, active and stopped sessions and the state digest.
- `verify-acks` reads an ack log from `radclient load --ack-log` and checks, for every session, that the
  last acknowledged event is in the replicated state (newer is fine: an event can commit without its ACK
  arriving). Exit code `1` and a list of the sessions if anything acknowledged is missing. The NAS id is the
  `nas.<name>.id` of the NAS entry the load came through.
- `--egress-host` is an address of this machine the members can reach: `localhost` locally, the container
  address inside Docker.

`AdminClient` is the library behind it; the test harness and the end-to-end tests use it directly.
