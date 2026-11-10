# sink-radius

Forwards the committed accounting of proxied realms to their home servers ([ADR 0037](../../docs/adr/0037-proxying.md)).
The cluster has already committed and answered every event; this sink sends it on as an Accounting-Request (its
original attributes, Acct-Delay-Time raised, a new Message-Authenticator) and counts a batch written only when every
request is acknowledged.

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
