# radiusward-units

`radiusward-units` reads the values that settings hold: durations, sizes, lists, hex bytes, and PEM certificates and
keys. The main configuration, the sinks, the identity stores and the tools all parse them through this module, so
`10s`, `64k` or a CA bundle mean the same in every key.

**Stability:** Internal: published as a dependency of `radiusward-auth-api`, `radiusward-export-api` and the radiusward server; it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward-auth-api` and `radiusward-export-api` bring it to plug-in
writers, and `radiusward-embedded` and the radiusward server bring it with the rest. Plug-ins that read their own
settings may call it to accept the same units as the built-in keys.

## What's inside

| Type | Role |
|---|---|
| `Units.duration(text, bare)` | `250ms`, `10s`, `5m`, `2h`, `1d`; `bare` is the unit of a number without one, or `null` to require a unit (except for `0`) |
| `Units.bytes(text)` | `512`, `64k`, `4m`, `1g` in bytes (powers of 1024, an optional `b`) |
| `Units.list(text)`, `Units.words(text)` | comma-separated items, trimmed, empty items left out; `words` also splits on spaces (for values such as URLs) |
| `Units.hex(text, length)` | hex digits, with or without `0x`, in either case; `length` is the expected byte count, `-1` for any |
| `Pem.certificates(path)`, `Pem.trustStore(path)` | the certificates of a PEM file in order (a chain, the certificate first); a key store trusting them |
| `Pem.privateKey(path)` | an unencrypted PKCS#8 key (`BEGIN PRIVATE KEY`): RSA, EC or EdDSA; any other format fails with the `openssl pkcs8` command that converts it |
| `Pem.clientContext(protocol, certificate, key, ca)` | a `TLS` or `DTLS` client `SSLContext`: our certificate and key when both are given, and the CAs the server must chain to |

Case and spaces between number and unit do not matter. Bad input throws `IllegalArgumentException` with a message
that names the expected form; these run when settings are read, never per packet.

## Example

```java
Duration timeout = Units.duration("10s", ChronoUnit.MILLIS);   // a bare "500" would mean 500 ms
long segment     = Units.bytes("128m");                        // 134217728
List<String> ids = Units.list("a, b, , c");                    // [a, b, c]
byte[] key       = Units.hex("0x000102030405060708090a0b0c0d0e0f", 16);

SSLContext tls = Pem.clientContext("TLS", Path.of("client.pem"), Path.of("client.key"), Path.of("ca.pem"));
```

## Requirements

Java 25. No dependencies.

## Learn more

- [Configuration](../docs/configuration.md): how durations and sizes are written in every key
- [ADR 0010: configuration](../docs/adr/0010-configuration.md)
- [radiusward-common](../common/README.md): `Config`, which reads the main settings through this module

## License

Apache-2.0.
