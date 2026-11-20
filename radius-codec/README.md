# radiusward-codec

`radiusward-codec` reads and writes RADIUS packets without allocating per packet. It validates a received datagram,
walks its attributes (vendor ones included), verifies and signs authenticators, extracts the accounting attributes in
one pass, decrypts and verifies PAP and CHAP credentials, and builds Accounting-Responses and Access replies. The
RADIUS server's receive path, the client and the tools all use it.

**Stability:** Internal: published as a dependency of `radiusward-client`, `radiusward-export-api` and the radiusward server; it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward-client` brings it (with `radiusward-eap` and
`radiusward-auth-api`) for sending packets in tests, and `radiusward-embedded` and the radiusward server bring it for
the receive path. Sink writers get what they need through `radiusward-export-api`; identity store writers use
`radiusward-auth-api`, which carries no RADIUS logic.

## What's inside

| Type | Role |
|---|---|
| `RadiusPacket` | reusable view over a received datagram; `wrap()` validates header and attribute framing once (RFC 2865 §3) and returns a `DecodeStatus` instead of throwing |
| `AttributeCursor` | walks attributes; flattens Vendor-Specific sub-attributes using each vendor's `format=t,l[,c]`; malformed VSA content is reported as one opaque attribute |
| `RadiusPacketEncoder` | writes packets into a `MutableDirectBuffer`: header, attributes, vendor attributes, Message-Authenticator |
| `RadiusAuthenticator` | Request/Response Authenticator (MD5) and Message-Authenticator (HMAC-MD5), constant-time comparison; one instance per thread |
| `AccountingResponses` | builds and signs the Accounting-Response for a request (same identifier, Proxy-State copied) |
| `AccessRequests` | an Access-Request's method (PAP, CHAP, MS-CHAP, MS-CHAPv2, EAP, ambiguous), User-Password decryption and encryption (RFC 2865 §5.2, 16–128 bytes), CHAP verification (RFC 1994; CHAP-Challenge or the Request Authenticator); statuses, never exceptions; plaintext copies zeroed |
| `AccessResponses` | builds and signs Access-Accept/Reject/Challenge: Message-Authenticator **first** (BlastRADIUS), the reply attributes, then every Proxy-State in order |
| `AttributeValues` | typed value readers; `octets64()` combines a counter with its gigawords |
| `AttributeText` | attribute values as operators write them (`Service-Type = Framed-User`) to bytes and back, by dictionary type; allocates, so for configuration, stores and tools only |
| `VendorFormats`, `RadiusCode`, `DecodeStatus` | vendor VSA layouts (from the dictionary or standard); packet code constants; the outcome of decoding |
| `attributes.*` | generated constants (`Ietf` and one class per vendor named on the hot-attribute list's `constants` line) and `AccountingAttributeExtractor` filling `AccountingFields` (see [radius-codegen](../radius-codegen/README.md)) |

**Generated code.** `radius-codegen` turns the dictionaries into `io.radiusward.radius.codec.attributes` at
`generate-sources`, driven by `src/main/codegen/hot-attributes.txt` (at most 64 fields until the presence mask is
widened). The output lives in `target/generated-sources` and is never committed.

**Guarantees, enforced by tests:** no allocation per packet (`HotPathAllocationIT`, 1M packets); the decoder never
throws or reads outside the datagram (jqwik fuzzing); results match aaa4j-radius (differential tests, also for
User-Password and Access replies) and the RFC 2865 / RFC 2104 vectors (including the §7.1 User-Password); 33 vendor
fixtures (11 vendors) round-trip byte-exactly. Line coverage ≥ 90 % (generated code excluded).

Not thread-safe by design: one set of instances per owning thread. Malformed input returns a status and the packet is
silently discarded, as RFC 2865 §3 requires.

## Example

```java
RadiusPacket packet = new RadiusPacket();                     // all of these are reused per thread
RadiusAuthenticator auth = new RadiusAuthenticator();
AccountingAttributeExtractor extractor = new AccountingAttributeExtractor(VendorFormats.from(dictionary));
AccountingFields fields = new AccountingFields();
AccountingResponses responses = new AccountingResponses(auth);

if (packet.wrap(buffer, 0, received) == DecodeStatus.OK
        && packet.code() == RadiusCode.ACCOUNTING_REQUEST
        && auth.verifyAccountingRequest(packet, secret)) {
    extractor.extract(packet, fields);
    long status = fields.statusType();                         // Ietf.ACCT_STATUS_TYPE_START, ...
    // ... after the cluster commits:
    int length = responses.encode(packet, out, 0, secret, false);
}

AccessRequests access = new AccessRequests();                 // Access-Request
AccessResponses replies = new AccessResponses(auth);
if (access.method(packet) == AccessRequests.METHOD_PAP) {
    int n = access.decryptUserPassword(packet, secret, password, 0);   // < 0: missing / malformed → drop
    // ... verify against the stored hash, decide ...
    int length = replies.encode(packet, RadiusCode.ACCESS_ACCEPT, replyAttributes, 0, replyLength, out, 0, secret);
}
```

## Requirements

Java 25. Runtime dependencies: Agrona (Apache-2.0) and `radiusward-dictionary`. The code generator and the bundled
dictionaries are needed at build time only.

## Learn more

- [ADR 0008: dictionaries, licensing and code generation](../docs/adr/0008-dictionaries-licensing-codegen.md)
- [ADR 0020: the authentication path](../docs/adr/0020-authentication-path.md)
- [Test strategy](../docs/testing/strategy.md): vendor fixtures and their format
- [radius-codegen](../radius-codegen/README.md), [radiusward-dictionary](../radius-dictionary/README.md),
  [radiusward-client](../client/README.md)

## License

Apache-2.0.
