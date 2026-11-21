# radiusward-client

A RADIUS client for development and tests that behaves as a NAS and as the devices behind it. It sends
Access-Requests (PAP, CHAP, MS-CHAPv2, and whole EAP logins with a built-in supplicant), Accounting-Requests from Start
to Stop, and Status-Server; retransmits as a NAS does; and accepts only answers whose authenticators verify. It also
listens for CoA and Disconnect-Requests. `radiusward-client` works against any RADIUS server, not only radiusward.

**Stability:** Public API: kept compatible within a minor version (until 1.0, a minor version may change it, with a
note in the release).

## Use it

```xml
<dependency>
    <groupId>io.radiusward</groupId>
    <artifactId>radiusward-client</artifactId>
    <!-- version from radiusward-bom; see the main README -->
    <scope>test</scope>
</dependency>
```

Gradle: `testImplementation("io.radiusward:radiusward-client")` (version from the BOM platform).

## Example

```java
try (RadiusClient client = RadiusClient.udp("127.0.0.1", 1812, "testing123")) {
    Response login = client.msChapV2("alice", "secret").orElseThrow();   // or pap, chap
    assert login.isAccept();
    login.string(25);                                                    // Class, Reply-Message, ...

    Response acct = client.send(client.accountingRequest().uint32(40, 1).attribute(44, "s-1")).orElseThrow();
    assert acct.isAcknowledgement();
}
```

## What's inside

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
| `EapLogin.teap(user, password)` | TEAP with Basic-Password-Auth or an inner EAP-GTC, every Crypto-Binding checked and answered |
| `EapLogin.pwd(user, password)` | EAP-pwd (group 19): the server's Confirm checked first, so a wrong password stops the device with an exception |
| `EapLogin.sim(card)`, `aka(card)`, `akaPrime(card)` | EAP-SIM, EAP-AKA and EAP-AKA′ with a simulated `SimCard`: the permanent identity (`1`, `0` or `6` before the IMSI, `realm(...)` after it), MILENAGE, the network checked (AUTN, the server's AT_MAC) |

A request of another method is answered with a Nak naming the login's. `trust(...)` sets the CAs the server must chain
to (or a self-signed server certificate itself); every TLS-based login needs it. TLS 1.2 or 1.3 (`tlsProtocol`), fragments of `fragmentSize`.

A `SimCard` holds the IMSI, Ki and OPc (or `SimCard.withOp(imsi, ki, op)`), and like a USIM the highest sequence number
it accepted: reuse the card across logins to see fresh sequence numbers, set `sqn(...)` ahead of the network to see a
resynchronisation. A card that does not trust the network answers with Authentication-Reject or Client-Error, so the
login ends rejected. AKA needs the cluster's sequence numbers (state version 8), so test it on a cluster.

```java
SimCard card = new SimCard("262011000000001", ki, opc);
EapResult r = client.eap(EapLogin.aka(card));
r.serverProved();  card.sqn();                                    // the network's AUTN and MAC; the SQN accepted
```

| Class | Role |
|---|---|
| `SimCard` | a simulated SIM or USIM: IMSI, Ki, OPc and the SQN it accepted |
| `EapLogin`, `EapResult` | what the device logs in with; how it ended, with rounds, reply, keys and the checks of the server |
| `EapSupplicant`, `TlsPeer` | the conversation; the JDK's TLS client in RFC 5216 framing (package-private) |
| `PeapInner`, `TtlsInner`, `TeapInner`, `PwdPeer`, `SimPeer` | one method's side of the conversation each, inside the tunnel or on its own (package-private) |

## Requirements

Java 25 and the JVM option `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` (the client and the codec read
packets with Agrona's buffers): Surefire's or Failsafe's `argLine`, Gradle's `jvmArgs`. Depends on `radiusward-codec`,
`radiusward-eap` and `radiusward-auth-api`.

## Learn more

- [radiusward-embedded](../embedded/README.md) and [radiusward-junit](../junit/README.md): a server to point it at, in the same JVM
- [ADR 0068: embedded radiusward and Maven Central](../docs/adr/0068-embedded-radiusward-and-maven-central.md)
- [Packets in tests](../docs/testing/strategy.md#packets-in-tests) and the vendor fixtures it replays

## License

Apache-2.0.
