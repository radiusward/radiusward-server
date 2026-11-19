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

Accounting sessions and an EAP supplicant follow ([plan](../docs/plans/embedded.md), E2a and E2b).
