# radiusward-junit

A JUnit 5 extension for tests against radiusward in the test's JVM. It starts an
[embedded radiusward](../embedded/README.md) for a test class or a single test, closes it afterwards (also after a
failure) and hands the tests what they ask for as parameters: the server and ready RADIUS clients.
`radiusward-junit` is only for tests; the server, the image and the chart do not use it.

**Stability:** Public API: kept compatible within a minor version (until 1.0, a minor version may change it, with a
note in the release).

## Use it

```xml
<dependency>
    <groupId>io.radiusward</groupId>
    <artifactId>radiusward-junit</artifactId>
    <!-- version from radiusward-bom; see the main README -->
    <scope>test</scope>
</dependency>
```

Gradle: `testImplementation("io.radiusward:radiusward-junit")` (version from the BOM platform).

It brings `radiusward-embedded` and `radiusward-client`; your build brings the JUnit engine.

## Example

```java
@Radiusward(users = "alice:secret")                   // one server for the class
class LoginTest {

    @Test
    void aliceLogsIn(RadiusClient nas) {               // a client of the Access-Request port
        assertThat(nas.pap("alice", "secret").orElseThrow().isAccept()).isTrue();
    }

    @Test
    void aSession(EmbeddedRadiusward radius, @Accounting RadiusClient acct) {
        acct.send(new AccountingSession("s-1").user("alice").start());
        assertThat(radius.activeSessions("alice")).hasSize(1);
    }
}
```

## What's inside

| `@Radiusward` | |
|---|---|
| `lifecycle` | `PER_CLASS` (default: one server for all tests of the class, about a second to start) or `PER_TEST` (a fresh one per test) |
| `users` | `name:password`; the password may contain `:` |
| `eap` | methods to offer; a TLS-based one gets the throwaway CA (`radius.ca()`) |
| `members`, `radiusServers` | a cluster of 3 members, several RADIUS servers |
| `settings` | any setting as `key=value` |

| Parameter | |
|---|---|
| `EmbeddedRadiusward` | the server: sessions, accounting, pausing, stopping members, CoA, the CA |
| `RadiusClient` | a client of the Access-Request port, closed after the test |
| `@Accounting RadiusClient` | a client of the Accounting-Request port |

The developer's own identity store, verifier or sinks, or anything else the builder offers, go through the extension
registered in code; a `static` field gives one server per class, an instance field one per test:

```java
@RegisterExtension
static RadiuswardExtension radius = RadiuswardExtension.configure(b -> b
        .identityStore(new MyUsers())
        .sink(new MyBillingSink()));
```

Test classes that JUnit runs in parallel each get their own server, directory and ports.

## Requirements

Java 25, JUnit Jupiter 6 (built and tested against 6.1), and the JVM option `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`
as for [radiusward-embedded](../embedded/README.md).

## Learn more

- [radiusward-embedded](../embedded/README.md): everything the server parameter offers
- [radiusward-client](../client/README.md): logins, accounting, EAP and CoA from the test
- [testing/embedded-consumer](../testing/embedded-consumer): a project that uses the extension

## License

Apache-2.0.
