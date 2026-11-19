# junit

`radiusward-junit`: a JUnit extension for tests against radiusward in the test's JVM ([ADR 0068](../docs/adr/0068-embedded-radiusward-and-maven-central.md),
[plan](../docs/plans/embedded.md)). It starts an [embedded radiusward](../embedded/README.md) for a test class or a
test, closes it afterwards (also after a failure) and gives the tests what they ask for as parameters. Only for tests:
the server, the image and the chart do not use it.

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

Test classes that JUnit runs in parallel each get their own server, directory and ports. The JVM needs
`--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`, as for the embedded server.
