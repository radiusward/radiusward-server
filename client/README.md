# client

`radiusward-client`: a RADIUS client for development and tests, behaving as a NAS
([ADR 0068](../docs/adr/0068-embedded-radiusward-and-maven-central.md)).

```java
try (RadiusClient client = RadiusClient.udp("127.0.0.1", 1812, "testing123")) {
    Response login = client.msChapV2("alice", "secret").orElseThrow();   // or pap, chap
    assert login.isAccept();
    login.string(25);                                                    // Class, Reply-Message, ...

    Response acct = client.send(client.accountingRequest().uint32(40, 1).attribute(44, "s-1")).orElseThrow();
    assert acct.isAcknowledgement();
}
```

| Class | Role |
|---|---|
| `RadiusClient` | UDP from one socket; sends again after the timeout (the identical datagram, as a NAS does) and accepts only an answer with the request's identifier whose Response Authenticator and Message-Authenticator verify; empty when none comes |
| `Response` | the answer's code, attributes (also vendor ones and repeated ones), the attempt that was answered and the time it took |
| `PacketBuilder` | signed requests and replies: attributes in the order added, User-Password hidden, CHAP and MS-CHAPv2, Message-Authenticator, Request and Response Authenticators |
| `Credentials` | PAP, CHAP and MS-CHAPv2 attributes as a NAS writes them; also used by radclient |
| `AccountingSession`, `AccountingEvent`, `TerminateCause` | a session's Start, Interim-Update and Stop as a NAS reports them (user, device and NAS identity, Event-Timestamp, session time, octets with Gigawords, terminate cause); an event fixed when it happened, so `delay(n)` is the NAS's retransmission of the same event; Accounting-On and -Off |
| `RecordedPacket` | packets recorded as hex (vendor fixtures, `radclient decode --fixture`), replayed with `RadiusClient.replay` under the client's secret |
| `CoaListener`, `CoaRequest` | the NAS side of CoA and Disconnect (RFC 5176): verifies requests with the secret, answers ACK, NAK with an Error-Cause, or nothing, and keeps what came |
| `ReceivedPacket` | what `Response` and `CoaRequest` share: code and attributes |

```java
AccountingSession s = new AccountingSession("s-1").user("alice").callingStationId("aa-bb-cc-dd-ee-ff");
client.send(s.start());
AccountingEvent interim = s.interim(Duration.ofMinutes(5), 1_000_000, 4_000_000);
client.send(interim);
client.send(interim.delay(3));                      // the NAS's retransmission: a server counts it once
client.send(s.stop(Duration.ofMinutes(10), 2_000_000, 8_000_000, TerminateCause.USER_REQUEST));

try (CoaListener nas = CoaListener.bind(0, "testing123")) {      // its port is the NAS entry's CoA port
    CoaRequest r = nas.await(1, Duration.ofSeconds(5)).getFirst();
    assert r.isDisconnect();
}
```

## EAP

`RadiusClient.eap(EapLogin)` runs a whole EAP login as a device does through a NAS: EAP-Message in Access-Requests, the
server's State, Access-Challenges until an Access-Accept or Access-Reject.

```java
EapResult r = client.eap(EapLogin.peap("alice", "secret")          // inner MS-CHAPv2; .inner(Inner.GTC)
        .trust(caCertificate)                                     // the server must chain to it
        .outerIdentity("anonymous@example.org"));
r.accepted();                                                     // or rejected(), or NO_ANSWER
r.response().orElseThrow().string(25);                            // the Accept's reply items
r.msk().equals(r.serverMsk());                                    // the keys a Wi-Fi access point gets
r.serverProved();  r.cryptoBound();                               // MS-CHAPv2's proof, PEAP's crypto-binding
```

| Login | Methods |
|---|---|
| `EapLogin.md5(user, password)` | EAP-MD5 |
| `EapLogin.tls(identity, key, certificate)` | EAP-TLS with a client certificate |
| `EapLogin.peap(user, password)` | PEAPv0 with MS-CHAPv2 or GTC inside, crypto-binding answered when the server sends it |
| `EapLogin.ttls(user, password)` | EAP-TTLS with PAP, CHAP, MS-CHAP or MS-CHAPv2 inside |

A request of another method is answered with a Nak naming the login's. `trust(...)` sets the CAs the server must chain
to; `trustAnyServer()` exists for experiments only. TLS 1.2 or 1.3 (`tlsProtocol`), fragments of `fragmentSize`.
TEAP, EAP-pwd and EAP-SIM/AKA follow ([plan](../docs/plans/embedded.md), E2b-2 and E2b-3).

| Class | Role |
|---|---|
| `EapLogin`, `EapResult` | what the device logs in with; how it ended, with rounds, reply, keys and the checks of the server |
| `EapSupplicant`, `TlsPeer` | the conversation; the JDK's TLS client in RFC 5216 framing (package-private) |
