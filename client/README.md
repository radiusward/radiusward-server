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

An EAP supplicant follows ([plan](../docs/plans/embedded.md), E2b).
