# radius-codec

Zero-allocation RADIUS codec for the accounting hot path.

| Class | Role |
|---|---|
| `RadiusPacket` | reusable view over a received datagram; `wrap()` validates header and attribute framing once (RFC 2865 §3) and returns a `DecodeStatus` instead of throwing |
| `AttributeCursor` | walks attributes; flattens Vendor-Specific sub-attributes using each vendor's `format=t,l[,c]`; malformed VSA content is reported as one opaque attribute |
| `RadiusPacketEncoder` | writes packets into a `MutableDirectBuffer` |
| `RadiusAuthenticator` | Request/Response Authenticator (MD5) and Message-Authenticator (HMAC-MD5), constant-time comparison; one instance per thread |
| `AccountingResponses` | builds and signs the Accounting-Response for a request (same identifier, Proxy-State copied) |
| `AttributeValues` | typed value readers; `octets64()` combines a counter with its gigawords |
| `VendorFormats` | vendor VSA layouts, from the dictionary or standard |
| `attributes.*` | generated constants and `AccountingAttributeExtractor` (see [radius-codegen](../radius-codegen/README.md)) |

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
```

**Guarantees, enforced by tests:** no allocation per packet (`HotPathAllocationIT`, 1M packets);
the decoder never throws or reads outside the datagram (jqwik fuzzing); results match aaa4j-radius
(differential tests) and the RFC 2865 / RFC 2104 vectors; 21 vendor fixtures round-trip byte-exactly.
Line coverage ≥ 90 % (generated code excluded).

Not thread-safe by design: one set of instances per owning thread.
